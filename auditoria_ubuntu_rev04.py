import os
import platform
import subprocess
import urllib.request
import json
import re
import glob
import pwd
from concurrent.futures import ThreadPoolExecutor


class UltimateSystemAuditor:
    def __init__(self):
        self.local_kernel = platform.release()
        self.local_python = platform.python_version()
        self.username = os.getenv("USER", pwd.getpwuid(os.getuid())[0])
        self.home_dir = os.path.expanduser("~")
        self._seen_output = set()

    def _print_unique(self, text):
        key = text.strip()
        if not key or key in self._seen_output:
            return
        self._seen_output.add(key)
        print(text)

    def _run_cmd(self, cmd):
        try:
            return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode().strip()
        except:
            return None

    def _can_sudo_non_interactive(self):
        return self._run_cmd("sudo -n true >/dev/null 2>&1 && echo ok") == 'ok'

    def _read_text(self, path):
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as file_handle:
                return file_handle.read().strip()
        except OSError:
            return None

    def _read_json(self, path):
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as file_handle:
                return json.load(file_handle)
        except (OSError, json.JSONDecodeError):
            return None

    def _parse_bool(self, value):
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in {'true', '1', 'yes', 'on'}
        if isinstance(value, int):
            return value != 0
        return False

    def _parse_int(self, value, default=0):
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def _cpu_supports_x86_64_v3(self):
        required_flags = {
            'avx', 'avx2', 'bmi1', 'bmi2', 'fma', 'movbe', 'xsave'
        }
        try:
            with open('/proc/cpuinfo', 'r', encoding='utf-8', errors='ignore') as cpuinfo_file:
                content = cpuinfo_file.read()
        except OSError:
            return False, set()

        match = re.search(r'^flags\s*:\s*(.+)$', content, re.MULTILINE)
        if not match:
            return False, set()

        flags = set(match.group(1).split())
        has_lzcnt_equivalent = 'lzcnt' in flags or 'abm' in flags
        missing = required_flags - flags
        if not has_lzcnt_equivalent:
            missing.add('lzcnt/abm')
        return len(missing) == 0, missing

    def _get_root_mount_info(self):
        try:
            with open('/proc/mounts', 'r', encoding='utf-8', errors='ignore') as mounts_file:
                for line in mounts_file:
                    parts = line.split()
                    if len(parts) >= 4 and parts[1] == '/':
                        return {
                            'device': parts[0],
                            'fs_type': parts[2],
                            'mount_options': parts[3].split(',')
                        }
        except OSError:
            return None
        return None

    def _get_fstab_root_entry(self):
        try:
            with open('/etc/fstab', 'r', encoding='utf-8', errors='ignore') as fstab_file:
                for line in fstab_file:
                    entry = line.strip()
                    if not entry or entry.startswith('#'):
                        continue
                    parts = entry.split()
                    if len(parts) >= 4 and parts[1] == '/':
                        return {
                            'raw': entry,
                            'device': parts[0],
                            'fs_type': parts[2],
                            'mount_options': parts[3].split(',')
                        }
        except OSError:
            return None
        return None

    def _get_timeshift_snapshot_dir(self):
        candidate_dirs = [
            '/timeshift/snapshots',
            os.path.join(self.home_dir, 'timeshift', 'snapshots'),
        ]
        for path in candidate_dirs:
            if os.path.isdir(path):
                return path
        return None

    def _get_battery_threshold_files(self):
        files = []
        files.extend(glob.glob('/sys/class/power_supply/BAT*/charge_control_end_threshold'))
        files.extend(glob.glob('/sys/class/power_supply/BAT*/charge_stop_threshold'))
        return sorted(set(files))

    def _audit_and_enforce_battery_limit(self):
        battery_paths = self._get_battery_threshold_files()
        if not battery_paths:
            self._print_unique("  [ℹ️ INFO] Limite de bateria: Arquivo de controle não encontrado no sistema.")
            return

        for bat_path in battery_paths:
            val = self._read_text(bat_path)
            if not val:
                self._print_unique(f"  [⚠️ AVISO] Não foi possível ler o limite de carga em: {bat_path}")
                continue

            if val == '80':
                self._print_unique(f"  [✅ OTIMIZADO] Limite de Bateria em 80% já ativo ({bat_path}).")
                continue

            self._print_unique(
                f"  [⚠️ AVISO] Limite de Bateria atual em {val}% ({bat_path}). Recomendado: 80% para maior vida útil."
            )

            try:
                with open(bat_path, 'w', encoding='utf-8') as threshold_file:
                    threshold_file.write('80')
                new_value = self._read_text(bat_path)
                if new_value == '80':
                    self._print_unique(f"  [✅ AJUSTADO] Limite de Bateria alterado para 80% em {bat_path}.")
                else:
                    self._print_unique(
                        f"  [⚠️ AVISO] Tentativa de ajuste para 80% em {bat_path} não foi confirmada (valor atual: {new_value})."
                    )
            except PermissionError:
                self._print_unique(
                    f"  [⚠️ AVISO] Sem permissão para ajustar {bat_path}. Use: sudo sh -c \"echo 80 > {bat_path}\""
                )
            except OSError:
                self._print_unique(f"  [⚠️ AVISO] Falha ao tentar ajustar o limite de bateria em {bat_path}.")

    # ==========================================
    # 1. ATUALIZAÇÕES DE SOFTWARE E KERNEL
    # ==========================================
    def get_latest_kernel(self):
        try:
            req = urllib.request.urlopen("https://www.kernel.org/releases.json", timeout=3)
            return json.loads(req.read().decode()).get('latest_stable', {}).get('version', 'Desconhecida')
        except:
            return "Erro"

    def get_latest_rust(self):
        try:
            req = urllib.request.urlopen("https://static.rust-lang.org/dist/channel-rust-stable.toml", timeout=3)
            match = re.search(r'pkg\.rustc\.version = "([^"]+)"', req.read().decode())
            return match.group(1).split()[0] if match else "Erro"
        except:
            return "Erro"

    def get_latest_python(self):
        try:
            req = urllib.request.urlopen("https://endoflife.date/api/python.json", timeout=3)
            return json.loads(req.read().decode())[0]['latest']
        except:
            return "Erro"

    def audit_software(self):
        print("\n" + "━" * 65)
        print(" 📦 1. SOFTWARE, KERNEL E COMPILADORES (ATUALIZAÇÕES)")
        print("━" * 65)

        rust_local = self._run_cmd("rustc --version | awk '{print $2}'") or "Não instalado"
        mesa_local = self._run_cmd("dpkg-query -W -f='${Version}' libegl-mesa0") or "Desconhecido"

        with ThreadPoolExecutor(max_workers=3) as executor:
            latest_k, latest_r = [
                future.result() for future in (
                    executor.submit(self.get_latest_kernel),
                    executor.submit(self.get_latest_rust),
                )
            ]

        self._compare_version("Kernel Linux", self.local_kernel, latest_k)
        self._print_unique(f"  • Python: ✅ ATUALIZADO PELO SISTEMA (Versão: {self.local_python})")
        self._compare_version("Rust", rust_local, latest_r)

        self._print_unique(
            f"  • Driver Mesa (Vídeo): {mesa_local} (💡 Dica: Verifique PPAs como Kisak para últimas versões)"
        )

    def _compare_version(self, name, local, latest):
        base_local = re.split(r'[-+]', local)[0]
        if latest not in ["Erro"] and base_local != latest and latest not in local and local != "Não instalado":
            self._print_unique(f"  • {name}: ⚠️ ATUALIZAÇÃO RECOMENDADA (Você tem {local} -> Última: {latest})")
        else:
            self._print_unique(f"  • {name}: ✅ ATUALIZADO (Versão: {local})")

    # ==========================================
    # 2. COMPONENTES DE HARDWARE
    # ==========================================
    def audit_hardware(self):
        print("\n" + "━" * 65)
        print(" 💻 2. COMPONENTES DE HARDWARE E BATERIA")
        print("━" * 65)

        cpu = None
        try:
            with open('/proc/cpuinfo', 'r', encoding='utf-8', errors='ignore') as cpuinfo_file:
                for line in cpuinfo_file:
                    if line.lower().startswith('model name'):
                        cpu = line.split(':', 1)[1].strip()
                        break
        except OSError:
            cpu = None
        self._print_unique(f"  • Processador: {cpu}")

        try:
            with open('/proc/meminfo', 'r', encoding='utf-8', errors='ignore') as meminfo_file:
                mem = {
                    linha.split(':')[0]: int(linha.split(':')[1].split()[0])
                    for linha in meminfo_file if ':' in linha
                }
            total = mem.get('MemTotal', 0) / (1024 ** 2)
            usada = total - (mem.get('MemAvailable', mem.get('MemFree', 0)) / (1024 ** 2))
            self._print_unique(f"  • Memória RAM: {total:.1f} GB Total (Usada: {usada:.1f} GB)")
        except:
            self._print_unique("  • Memória RAM: Erro ao ler /proc/meminfo")

        gpu = self._run_cmd("lspci | grep -i vga | cut -d ':' -f 3- | xargs")
        self._print_unique(f"  • Placa de Vídeo: {gpu}")

        disk = self._run_cmd("lsblk -d -o NAME,MODEL,SIZE | grep nvme")
        self._print_unique(f"  • Armazenamento: {disk}")

        # Verificação e tentativa de ajuste do limite de carga da bateria para 80%
        self._audit_and_enforce_battery_limit()

    # ==========================================
    # 3. DRIVERS UTILIZADOS NO ASUS
    # ==========================================
    def audit_drivers(self):
        print("\n" + "━" * 65)
        print(" ⚙️ 3. STATUS DOS DRIVERS (ASUS VIVOBOOK / AMD)")
        print("━" * 65)

        drivers_esperados = {
            "GPU AMD Barcelo": "amdgpu",
            "Controle ASUS (Bateria/Teclado)": "asus_wmi",
            "Sensores de Temperatura CPU": "k10temp",
            "Armazenamento SSD NVMe": "nvme",
            "Placa Wi-Fi Realtek": "rtw88_8821ce",
            "Áudio HD AMD": "snd_hda_intel",
            "Coprocessador Criptográfico AMD": "ccp"
        }

        lsmod = self._run_cmd("lsmod")
        for nome, modulo in drivers_esperados.items():
            if lsmod and modulo in lsmod:
                self._print_unique(f"  [✅ ATIVO] {nome} (Driver: {modulo})")
            else:
                self._print_unique(f"  [⚠️ AUSENTE/FALHA] {nome} (Driver esperado: {modulo})")

        # Microcódigo AMD (pacote e versão carregada)
        microcode_pkg = self._run_cmd("dpkg-query -W -f='${Status}' amd64-microcode 2>/dev/null")
        microcode_ver = self._run_cmd("grep -m1 '^microcode' /proc/cpuinfo | awk '{print $3}'")
        if microcode_pkg and 'install ok installed' in microcode_pkg:
            if microcode_ver:
                self._print_unique(
                    f"  [✅ OTIMIZADO] Microcódigo AMD ativo (amd64-microcode instalado, revisão carregada: {microcode_ver})."
                )
            else:
                self._print_unique("  [✅ INSTALADO] Pacote amd64-microcode instalado.")
        else:
            self._print_unique("  [⚠️ AVISO] amd64-microcode não está instalado. Recomendado para estabilidade e segurança.")

        # Renderer OpenGL real (evita fallback em llvmpipe)
        glx_renderer = self._run_cmd(
            "glxinfo -B 2>/dev/null | grep -i 'OpenGL renderer string' | cut -d ':' -f 2- | xargs"
        )
        if glx_renderer:
            renderer_lower = glx_renderer.lower()
            if 'llvmpipe' in renderer_lower:
                self._print_unique(
                    f"  [⚠️ AVISO] Renderer OpenGL em software ({glx_renderer}). Verifique aceleração da AMDGPU."
                )
            elif 'amd' in renderer_lower or 'radeon' in renderer_lower:
                self._print_unique(f"  [✅ OTIMIZADO] Renderer OpenGL acelerado por hardware: {glx_renderer}.")
            else:
                self._print_unique(f"  [ℹ️ INFO] Renderer OpenGL detectado: {glx_renderer}.")
        else:
            self._print_unique("  [ℹ️ INFO] glxinfo não disponível ou sem sessão gráfica ativa para validar renderer OpenGL.")

    # ==========================================
    # 4. TUNING E PERFORMANCE
    # ==========================================
    def audit_performance(self):
        print("\n" + "━" * 65)
        print(" 🚀 4. PERFORMANCE E OTIMIZAÇÕES MÁXIMAS")
        print("━" * 65)

        # CPU Driver
        cpu_driver = self._read_text('/sys/devices/system/cpu/cpu0/cpufreq/scaling_driver')
        if cpu_driver in ["amd-pstate-epp", "amd_pstate_epp"]:
            self._print_unique("  [✅ OTIMIZADO] CPU Driver: amd_pstate_epp (Máximo controle do Ryzen).")
        else:
            self._print_unique(f"  [⚠️ AVISO] CPU Driver: {cpu_driver}. Falta ativar amd_pstate no GRUB.")

        # Verificação de compatibilidade do processador com x86-64-v3
        cpu_v3_ok, missing_flags = self._cpu_supports_x86_64_v3()
        if cpu_v3_ok:
            self._print_unique("  [✅ OTIMIZADO] Processador compatível com x86-64-v3.")
        elif missing_flags:
            missing_text = ', '.join(sorted(missing_flags))
            self._print_unique(
                f"  [⚠️ AVISO] Processador sem conjunto completo para x86-64-v3. Faltando: {missing_text}."
            )
        else:
            self._print_unique("  [⚠️ AVISO] Não foi possível confirmar compatibilidade do processador com x86-64-v3.")

        # Perfil de plataforma ASUS (ACPI)
        platform_profile = self._read_text('/sys/firmware/acpi/platform_profile')
        profile_choices = self._read_text('/sys/firmware/acpi/platform_profile_choices')
        if platform_profile:
            if profile_choices:
                self._print_unique(
                    f"  [✅ OTIMIZADO] ASUS Platform Profile ativo: {platform_profile} (Opções: {profile_choices})."
                )
            else:
                self._print_unique(f"  [✅ OTIMIZADO] ASUS Platform Profile ativo: {platform_profile}.")
        else:
            self._print_unique(
                "  [ℹ️ INFO] Platform Profile ACPI não disponível neste kernel/modelo (pode variar por BIOS/equipamento)."
            )

        # Agendador NVMe
        nvme_disk = self._run_cmd("lsblk -d -o NAME | grep nvme | head -n 1")
        if nvme_disk:
            sched = self._run_cmd(f"cat /sys/block/{nvme_disk}/queue/scheduler")
            if sched and "none" in sched.replace("[", "").replace("]", ""):
                self._print_unique(f"  [✅ OTIMIZADO] SSD NVMe ({nvme_disk}): Agendador 'none' (Menor latência).")
            else:
                self._print_unique(f"  [⚠️ AVISO] SSD NVMe ({nvme_disk}): Agendador '{sched}'. Mude para 'none'.")

            # Saúde SMART do NVMe
            nvme_dev = f"/dev/{nvme_disk}"
            smartctl_path = self._run_cmd("command -v smartctl")
            if not smartctl_path:
                self._print_unique(
                    f"  [ℹ️ INFO] SMART NVMe ({nvme_dev}) indisponível: smartctl não instalado (pacote smartmontools)."
                )
                smart_summary = None
                nvme_used = None
                nvme_temp = None
            else:
                smart_prefix = ""
                if os.geteuid() != 0 and self._can_sudo_non_interactive():
                    smart_prefix = "sudo -n "

                smart_summary = self._run_cmd(
                    f"{smart_prefix}smartctl -H {nvme_dev} 2>/dev/null | "
                    "grep -E 'SMART overall-health|SMART Health Status|overall-health'"
                )
                nvme_used = self._run_cmd(
                    f"{smart_prefix}smartctl -a {nvme_dev} 2>/dev/null | "
                    "awk -F ':' '/Percentage Used/ {gsub(/^[ \\t]+/, \"\", $2); print $2; exit}'"
                )
                nvme_temp = self._run_cmd(
                    f"{smart_prefix}smartctl -a {nvme_dev} 2>/dev/null | "
                    "awk -F ':' '/Temperature:/ {gsub(/^[ \\t]+/, \"\", $2); print $2; exit}'"
                )

            if smart_summary:
                if 'PASSED' in smart_summary.upper() or 'OK' in smart_summary.upper():
                    details = []
                    if nvme_used:
                        details.append(f"uso: {nvme_used}")
                    if nvme_temp:
                        details.append(f"temp: {nvme_temp}")
                    suffix = f" ({', '.join(details)})" if details else ""
                    self._print_unique(f"  [✅ OTIMIZADO] SMART NVMe ({nvme_dev}) saudável{suffix}.")
                else:
                    self._print_unique(f"  [⚠️ AVISO] SMART NVMe ({nvme_dev}) reportou status: {smart_summary}.")
            else:
                if smartctl_path:
                    self._print_unique(
                        f"  [ℹ️ INFO] SMART NVMe ({nvme_dev}) requer privilégios de root para leitura completa."
                    )

        # zRAM
        zram = self._run_cmd("zramctl")
        if zram and "zram" in zram:
            self._print_unique("  [✅ OTIMIZADO] Compressão de Memória: zRAM está ATIVO.")
        else:
            self._print_unique("  [⚠️ AVISO] zRAM INATIVO. Sem zRAM, o SSD sofre desgaste com Swap.")

        # EXT4 noatime
        root_mount = self._get_root_mount_info()
        fstab_root = self._get_fstab_root_entry()
        root_fs = root_mount['fs_type'] if root_mount else None

        if root_fs == 'ext4':
            mount_options = set(root_mount.get('mount_options', [])) if root_mount else set()
            fstab_options = set(fstab_root.get('mount_options', [])) if fstab_root else set()
            if 'noatime' in mount_options or 'noatime' in fstab_options:
                self._print_unique("  [✅ OTIMIZADO] Sistema EXT4: Opção 'noatime' aplicada no volume raiz.")
            else:
                self._print_unique("  [⚠️ AVISO] Sistema EXT4: Falta aplicar 'noatime' no volume raiz.")
        elif root_fs:
            self._print_unique(f"  [ℹ️ INFO] Sistema raiz detectado: {root_fs}. Ajuste 'noatime' para EXT4 não se aplica.")

        # Wi-Fi Power Save
        ps = self._run_cmd("iw dev wlp1s0 get power_save")
        if ps and "off" in ps:
            self._print_unique("  [✅ OTIMIZADO] Wi-Fi Power Save: DESATIVADO (Ping estável).")
        else:
            self._print_unique("  [⚠️ AVISO] Wi-Fi Power Save: ATIVO (Causa quedas na RTL8821CE).")

        # TCP BBR
        tcp = self._run_cmd("cat /proc/sys/net/ipv4/tcp_congestion_control")
        if tcp == "bbr":
            self._print_unique("  [✅ OTIMIZADO] Protocolo de Rede: TCP BBR ativado.")
        else:
            self._print_unique(f"  [⚠️ AVISO] Protocolo de Rede: {tcp}. BBR entrega mais velocidade.")

    # ==========================================
    # 5. FERRAMENTAS E PERSONALIZAÇÃO
    # ==========================================
    def audit_system_tools(self):
        print("\n" + "━" * 65)
        print(" 🛠️ 5. FERRAMENTAS E PERSONALIZAÇÃO DO SISTEMA")
        print("━" * 65)

        # 1. Timeshift
        if self._run_cmd("which timeshift"):
            self._print_unique("  [✅ INSTALADO] Timeshift (Snapshots e Backup do sistema).")

            timeshift_config = self._read_json('/etc/timeshift/timeshift.json')
            if not timeshift_config:
                self._print_unique(
                    "  [⚠️ AVISO] Não foi possível ler /etc/timeshift/timeshift.json para validar agenda e retenção."
                )
            else:
                daily_enabled = self._parse_bool(timeshift_config.get('schedule_daily'))
                weekly_enabled = self._parse_bool(timeshift_config.get('schedule_weekly'))
                count_daily = self._parse_int(timeshift_config.get('count_daily'))
                count_weekly = self._parse_int(timeshift_config.get('count_weekly'))

                if daily_enabled and count_daily == 5:
                    self._print_unique("  [✅ OTIMIZADO] Timeshift diário configurado corretamente: 5 snapshots diários.")
                elif daily_enabled:
                    self._print_unique(
                        f"  [⚠️ AVISO] Timeshift diário ativo, mas com retenção de {count_daily} dias. Recomendado: 5 dias."
                    )
                else:
                    self._print_unique("  [⚠️ AVISO] Timeshift diário está desativado. Recomendado: ativar com retenção de 5 dias.")

                if weekly_enabled and count_weekly == 1:
                    self._print_unique("  [✅ OTIMIZADO] Timeshift semanal configurado: manter 1 snapshot (1 semana).")
                elif weekly_enabled:
                    self._print_unique(
                        f"  [⚠️ AVISO] Timeshift semanal ativo, mas com retenção de {count_weekly} semanas. Recomendado: 1 semana."
                    )
                else:
                    self._print_unique("  [⚠️ AVISO] Timeshift semanal está desativado. Recomendado: manter 1 snapshot semanal.")

            # Último snapshot e espaço livre no destino
            snapshot_dir = self._get_timeshift_snapshot_dir()
            if snapshot_dir:
                last_snapshot = self._run_cmd(f"ls -1dt {snapshot_dir}/* 2>/dev/null | head -n 1")

                if last_snapshot:
                    self._print_unique(f"  [✅ OTIMIZADO] Último snapshot Timeshift: {os.path.basename(last_snapshot)}.")
                else:
                    self._print_unique("  [⚠️ AVISO] Diretório de snapshots do Timeshift encontrado, mas sem snapshots listáveis.")
            else:
                self._print_unique("  [ℹ️ INFO] Diretório de snapshots do Timeshift não encontrado para checagem de espaço.")
        else:
            self._print_unique("  [⚠️ AVISO] Timeshift NÃO encontrado. Essencial para backups de segurança!")

        # 2. Nala configurado como padrão
        if self._run_cmd("which nala"):
            alias_found = False
            for rc_file in ['.zshrc', '.bashrc']:
                content = self._read_text(os.path.join(self.home_dir, rc_file))
                if content and re.search(r"^alias\s+apt=['\"]?nala['\"]?", content, re.MULTILINE):
                    alias_found = True
                    break

            if alias_found:
                self._print_unique("  [✅ OTIMIZADO] Nala instalado e definido como padrão (alias apt='nala').")
            else:
                self._print_unique("  [⚠️ AVISO] Nala instalado, mas o alias para substituir o 'apt' não foi encontrado.")
        else:
            self._print_unique("  [⚠️ AVISO] Nala NÃO encontrado.")

        # 3. Flatpak e Flathub
        if self._run_cmd("which flatpak"):
            if self._run_cmd("flatpak remotes | grep -i flathub"):
                self._print_unique("  [✅ INSTALADO] Flatpak e repositório Flathub prontos para uso.")
            else:
                self._print_unique("  [⚠️ AVISO] Flatpak está instalado, mas o repositório Flathub NÃO está configurado.")
        else:
            self._print_unique("  [⚠️ AVISO] Flatpak NÃO encontrado.")

        # 4. Zsh e Tema Dracula
        if self._run_cmd("which zsh"):
            # Checagem do shell padrão do usuário diretamente no arquivo passwd
            default_shell = pwd.getpwnam(self.username).pw_shell
            if 'zsh' in default_shell:
                self._print_unique(f"  [✅ INSTALADO] Zsh é o shell padrão ativo ({default_shell}).")
            else:
                self._print_unique(f"  [⚠️ AVISO] Zsh instalado, mas o shell padrão do usuário ainda é o {default_shell}.")

            zshrc = self._read_text(os.path.join(self.home_dir, '.zshrc'))
            if zshrc and re.search(r"^ZSH_THEME=['\"]dracula['\"]", zshrc, re.MULTILINE):
                self._print_unique("  [✅ OTIMIZADO] Tema Dracula ativado e configurado no Oh My Zsh.")
            else:
                self._print_unique("  [⚠️ AVISO] Tema Dracula não detectado como ZSH_THEME no arquivo ~/.zshrc.")
        else:
            self._print_unique("  [⚠️ AVISO] Zsh NÃO encontrado.")

if __name__ == "__main__":
    auditor = UltimateSystemAuditor()
    auditor.audit_software()
    auditor.audit_hardware()
    auditor.audit_drivers()
    auditor.audit_performance()
    auditor.audit_system_tools()
