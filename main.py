import tkinter as tk
from tkinter import filedialog
import paramiko
from pathlib import Path
import os
from datetime import datetime
import yaml
import threading
import sys


def reset_upload_text(text_widget, placeholder_text):
    if text_widget.get("1.0", tk.END).strip() == "":
        text_widget.delete(1.0, tk.END)
        text_widget.insert(tk.END, placeholder_text)
        text_widget.tag_configure("placeholder", font=("Helvetica Bold", 15, "italic"), foreground="gray")
        text_widget.tag_add("placeholder", "1.0", "end")


def open_config_file(event):
    # 获取当前脚本所在目录
    config_file_path = "config.txt"
    print(config_file_path)

    try:
        os.startfile(config_file_path)  # 使用默认程序打开文件
    except Exception as e:
        print(f"Error opening config.txt: {str(e)}")


def remote_path_exists(sftp, path):
    try:
        sftp.stat(path)
        return True
    except FileNotFoundError:
        return False


def create_remote_path(sftp, path):
    # 逐层创建远程路径
    parts = path.split('/')
    for i in range(1, len(parts)):
        partial_path = '/'.join(parts[:i + 1])
        if not remote_path_exists(sftp, partial_path):
            sftp.mkdir(partial_path)


def log_contains(sftp, log_path, keyword):
    try:
        with sftp.file(log_path, "r") as f:
            content = f.read()
            return keyword in content
    except Exception as e:
        return False


def set_script_permissions(hostname, port, username, password, script_path):
    try:
        transport = paramiko.Transport((hostname, port))
        transport.connect(username=username, password=password)
        ssh = paramiko.SSHClient()
        ssh._transport = transport

        # Execute the chmod command on the script
        command = f"chmod +x {script_path}"
        stdin, stdout, stderr = ssh.exec_command(command)

        # You can print the output or handle any errors here
        print(stdout.read().decode("utf-8"))

        transport.close()
    except Exception as e:
        print(f"Error: {str(e)}")


class FileUploaderApp:
    def __init__(self, root):
        self.open_config_button = None
        self.bottom_frame = None
        self.log_text = None
        self.status_label = None
        self.publish_button = None
        self.root = root
        self.root.title("站端后台升级程序")
        self.root.geometry("800x900")  # 设置窗口大小

        self.uploaded_client = False
        self.uploaded_client_yml = False
        self.uploaded_server = False
        self.uploaded_server_yml = False

        self.client_text = tk.Text(self.root, height=4, width=80)  # 添加这些行
        self.client_yml_text = tk.Text(self.root, height=4, width=80)
        self.server_text = tk.Text(self.root, height=4, width=80)
        self.server_yml_text = tk.Text(self.root, height=4, width=80)

        self.setup_ui()

    def create_input_field(self, placeholder, event_handler):
        text_widget = tk.Text(self.root, height=4, width=80)
        text_widget.pack(pady=(20, 0))
        text_widget.insert("1.0", placeholder)
        text_widget.tag_configure("placeholder", font=("Helvetica Bold", 15, "italic"), foreground="gray")
        text_widget.tag_add("placeholder", "1.0", "end")
        text_widget.bind("<Button-1>", event_handler)
        return text_widget

    def setup_ui(self):
        # self.client_text = tk.Text(self.root, height=4, width=80)
        # self.client_text.pack(pady=(20, 0))
        # self.client_text.insert("1.0", "请上传client包")
        # self.client_text.tag_configure("placeholder", font=("Helvetica Bold", 15, "italic"), foreground="gray")
        # self.client_text.tag_add("placeholder", "1.0", "end")
        # self.client_text.bind("<Button-1>", self.upload_client_jar)

        self.client_text = self.create_input_field("请上传client包", self.upload_client_jar)
        # self.create_input_field(self.client_text, "请上传client包", self.upload_client_jar)

        self.client_yml_text = self.create_input_field("请上传client包的application.yml文件", self.upload_client_yml)
        self.server_text = self.create_input_field("请上传server包", self.upload_server_jar)
        self.server_yml_text = self.create_input_field("请上传server包的application.yml文件", self.upload_server_yml)

        # 创建一个 Frame 作为容器，包含发布按钮和导出日志按钮
        self.button_frame = tk.Frame(self.root)
        self.button_frame.pack(pady=(0, 10))

        # "发布"按钮
        self.publish_button = tk.Button(self.button_frame, text="发布", command=self.start_publishing,
                                        state=tk.DISABLED, width=20, bg="orange")
        self.publish_button.grid(row=0, column=0, padx=(0, 10))

        # "导出client日志"按钮
        self.export_client_log_button = tk.Button(self.button_frame, text="导出client日志",
                                                  command=self.export_client_log,
                                                  width=20, bg="orange")
        self.export_client_log_button.grid(row=0, column=1, padx=(0, 10))

        # "导出server日志"按钮
        self.export_server_log_button = tk.Button(self.button_frame, text="导出server日志",
                                                  command=self.export_server_log,
                                                  width=20, bg="orange")
        self.export_server_log_button.grid(row=0, column=2)

        self.status_label = tk.Label(self.root, text="")
        self.status_label.pack()

        self.log_text = tk.Text(self.root, height=30, width=80)
        self.log_text.pack()

        # 创建一个 Frame 作为容器
        self.bottom_frame = tk.Frame(self.root)
        self.bottom_frame.place(x=700, y=830)  # 设置按钮的绝对坐标

        # 创建一个 Label 作为按钮，显示记事本图标
        self.open_config_button = tk.Label(self.bottom_frame, text="配置文件", font=("Arial", 10, "bold"), fg="white",
                                           bg="grey", padx=10, pady=5, relief="raised")
        self.open_config_button.pack()
        self.open_config_button.bind("<Button-1>", open_config_file)

    # 在 FileUploaderApp 类中添加以下方法
    def export_client_log(self):
        # 获取当前脚本所在目录
        config_file_path = "config.txt"
        with open(config_file_path, 'r') as config_file:
            config = {}
            for line in config_file:
                key, value = line.strip().split('=')
                config[key] = value
        client_dir = config.get('client_dir', '')
        self.export_log(f"{client_dir}/logs","client.log")

    def export_server_log(self):
        # 获取当前脚本所在目录
        config_file_path = "config.txt"
        with open(config_file_path, 'r') as config_file:
            config = {}
            for line in config_file:
                key, value = line.strip().split('=')
                config[key] = value
        server_dir = config.get('server_dir', '')
        self.export_log(f"{server_dir}/logs", "server.log")

    def export_log(self, log_dir, log_filename):
        try:
            self.log_text.insert(tk.END, f"正在导出 {log_filename}...\n")

            # 获取当前脚本所在目录
            config_file_path = "config.txt"
            with open(config_file_path, 'r') as config_file:
                config = {}
                for line in config_file:
                    key, value = line.strip().split('=')
                    config[key] = value

            hostname = config.get('hostname', '')
            username = config.get('username', '')
            password = config.get('password', '')

            if not hostname or not username or not password:
                self.log_text.insert(tk.END, "请确保config.txt中配置了正确的hostname、username、password\n")
                return

            log_remote_path = f"{log_dir}/{log_filename}"

            transport = paramiko.Transport((hostname, 22))
            transport.connect(username=username, password=password)
            sftp = paramiko.SFTPClient.from_transport(transport)

            local_save_path = f"{log_filename}_{datetime.now().strftime('%Y%m%d%H%M%S')}.log"

            # 下载日志文件到本地
            sftp.get(log_remote_path, local_save_path)
            self.log_text.insert(tk.END, f"{log_filename} 导出成功，保存为 {local_save_path}\n")

            transport.close()
        except Exception as e:
            self.log_text.insert(tk.END, f"导出 {log_filename} 失败：{str(e)}\n")

    def start_publishing(self):
        self.publish_button.config(state=tk.DISABLED, text="发布中...", width=20, bg="orange")
        thread = threading.Thread(target=self.publish)
        thread.start()

    def upload_client_jar(self, event):
        file_path = filedialog.askopenfilename(filetypes=[("Jar Files", "*.jar")])
        if file_path:
            self.client_text.delete(1.0, tk.END)
            self.client_text.insert(tk.END, file_path)
            self.uploaded_client = True
        else:
            self.uploaded_client = False
            reset_upload_text(self.client_text, "请上传client包")
        self.check_publish_button_state()

    def upload_client_yml(self, event):
        file_path = filedialog.askopenfilename(filetypes=[("YAML Files", "*.yml")])
        if file_path:
            self.client_yml_text.delete(1.0, tk.END)
            self.client_yml_text.insert(tk.END, file_path)
            self.uploaded_client_yml = True
        else:
            self.uploaded_client_yml = False
            reset_upload_text(self.client_text, "请上传client包的application.yml文件")
        self.check_publish_button_state()

    def upload_server_jar(self, event):
        file_path = filedialog.askopenfilename(filetypes=[("Jar Files", "*.jar")])
        if file_path:
            self.server_text.delete(1.0, tk.END)
            self.server_text.insert(tk.END, file_path)
            self.uploaded_server = True
        else:
            self.uploaded_server = False
            reset_upload_text(self.server_text, "请上传server包")
        self.check_publish_button_state()

    def upload_server_yml(self, event):
        file_path = filedialog.askopenfilename(filetypes=[("YAML Files", "*.yml")])
        if file_path:
            self.server_yml_text.delete(1.0, tk.END)
            self.server_yml_text.insert(tk.END, file_path)
            self.uploaded_server_yml = True
        else:
            self.uploaded_server_yml = False
            reset_upload_text(self.server_yml_text, "请上传server包的application.yml文件")
        self.check_publish_button_state()

    def check_publish_button_state(self):
        if self.uploaded_client or self.uploaded_server:
            self.publish_button.config(state=tk.NORMAL)

    def publish(self):
        client_path = self.client_text.get("1.0", tk.END).strip()
        client_yml_path = self.client_yml_text.get("1.0", tk.END).strip()
        server_path = self.server_text.get("1.0", tk.END).strip()
        server_yml_path = self.server_yml_text.get("1.0", tk.END).strip()

        try:
            self.log_text.delete(1.0, tk.END)  # 清空日志文本框

            self.log_text.insert(tk.END, "初始化...\n")
            with open('config.txt', 'r') as config_file:
                config = {}
                for line in config_file:
                    key, value = line.strip().split('=')
                    config[key] = value

            hostname = config.get('hostname', '')
            username = config.get('username', '')
            password = config.get('password', '')
            client_dir = config.get('client_dir', '')
            server_dir = config.get('server_dir', '')

            if not hostname or not username or not password or not client_dir or not server_dir:
                self.log_text.insert(tk.END,
                                     "请确保config.txt中配置了正确的hostname、username、password、client_dir、server_dir\n")
                return

            self.log_text.insert(tk.END, "正在登陆服务器...\n")

            transport = paramiko.Transport((hostname, 22))
            transport.connect(username=username, password=password)
            sftp = paramiko.SFTPClient.from_transport(transport)

            if self.uploaded_client_yml:
                self.log_text.insert(tk.END, "读取client包配置文件...\n")
                remote_client_dir_yml = f"{client_dir}/config"
                client_yml_filename = Path(client_yml_path).name

                remote_client_yml_path = f"{remote_client_dir_yml}/{client_yml_filename}"

                # Read the existing server's application.yml content
                client_existing_yml_path = f"{remote_client_dir_yml}/application.yml"
                client_existing_yml_content = self.read_remote_file(sftp, client_existing_yml_path)

                # Extract spring.datasource config from existing server's application.yml
                existing_yaml = yaml.safe_load(client_existing_yml_content)
                existing_datasource = existing_yaml.get('spring', {}).get('datasource', {})

                # Read the new local application.yml content
                client_new_yml_content = self.read_local_file(client_yml_path)

                # Replace only the spring.datasource content in the new local application.yml
                client_updated_yml_content = self.replace_datasource_config(client_new_yml_content, existing_datasource)

                self.log_text.insert(tk.END, "备份client包配置文件...\n")
                # Backup the existing application.yml on the server
                self.backup_file(sftp, remote_client_yml_path)

                self.log_text.insert(tk.END, "合并client包application.yml...\n")
                # Upload the updated application.yml to the server
                self.write_remote_file(sftp, remote_client_yml_path, client_updated_yml_content)

            if self.uploaded_server_yml:
                self.log_text.insert(tk.END, "读取server包配置文件...\n")
                remote_server_dir_yml = f"{server_dir}/config"
                server_yml_filename = Path(server_yml_path).name

                remote_server_yml_path = f"{remote_server_dir_yml}/{server_yml_filename}"

                # Read the existing server's application.yml content
                server_existing_yml_path = f"{remote_server_dir_yml}/application.yml"
                server_existing_yml_content = self.read_remote_file(sftp, server_existing_yml_path)

                # Extract spring.datasource config from existing server's application.yml
                existing_yaml = yaml.safe_load(server_existing_yml_content)
                existing_datasource = existing_yaml.get('spring', {}).get('datasource', {})

                # Read the new local application.yml content
                server_new_yml_content = self.read_local_file(server_yml_path)

                # Replace only the spring.datasource content in the new local application.yml
                server_updated_yml_content = self.replace_datasource_config(server_new_yml_content, existing_datasource)

                self.log_text.insert(tk.END, "备份server包配置文件...\n")
                # Backup the existing application.yml on the server
                self.backup_file(sftp, remote_server_yml_path)

                self.log_text.insert(tk.END, "合并server包application.yml...\n")
                # Upload the updated application.yml to the server
                self.write_remote_file(sftp, remote_server_yml_path, server_updated_yml_content)

            if self.uploaded_client:
                self.log_text.insert(tk.END, "准备构建client包...\n")
                remote_client_dir_jar = f"{client_dir}"
                client_filename = Path(client_path).name
                remote_client_jar_path = f"{remote_client_dir_jar}/{client_filename}"

                self.log_text.insert(tk.END, "备份client包...\n")
                # 备份服务器上的文件
                self.backup_file(sftp, remote_client_jar_path)

                self.log_text.insert(tk.END, "上传client包...\n")
                # 上传新的客户端包文件
                self.upload_file(sftp, client_path, remote_client_jar_path)

                self.log_text.insert(tk.END, "重启client包...\n")
                # 执行 springboot.sh restart 操作
                self.restart_project(sftp, hostname, username, password, remote_client_dir_jar, client_filename,
                                        "8081")
                self.log_text.insert(tk.END, "client包发布成功...\n")

            if self.uploaded_server:
                self.log_text.insert(tk.END, "准备构建server包...\n")
                remote_server_dir_jar = f"{server_dir}"
                server_filename = Path(server_path).name
                remote_server_jar_path = f"{remote_server_dir_jar}/{server_filename}"

                self.log_text.insert(tk.END, "备份server包...\n")
                # 备份服务器上的文件
                self.backup_file(sftp, remote_server_jar_path)

                self.log_text.insert(tk.END, "上传server包...\n")
                # 上传新的服务器包文件
                self.upload_file(sftp, server_path, remote_server_jar_path)

                self.log_text.insert(tk.END, "重启server包...\n")
                # 执行 springboot.sh restart 操作
                self.restart_project(sftp, hostname, username, password, remote_server_dir_jar, server_filename,
                                        "8082")
                self.log_text.insert(tk.END, "server包发布成功...\n")

            transport.close()
        except Exception as e:
            self.log_text.insert(tk.END, f"上传失败：{str(e)}\n")
        finally:
            self.publish_button.config(state=tk.NORMAL, text="重新发布", width=20, bg="orange")

    def update_log_text(self):
        current_log = self.log_text.get("1.0", tk.END).strip()

        if current_log == "...":
            self.log_text.delete(1.0, tk.END)
        else:
            self.log_text.insert(tk.END, ".")

        self.root.after(self.log_update_interval, self.update_log_text)  # 继续定时更新日志内容

    def backup_file(self, sftp, remote_path):
        try:
            strftime = datetime.now().strftime("%Y%m%d%H%M%S")
            backup_path = f"{remote_path}_{strftime}"  # 构造备份文件路径
            sftp.rename(remote_path, backup_path)  # 重命名文件为备份文件
            self.log_text.insert(tk.END, f"文件备份成功：{backup_path}\n")
        except Exception as e:
            self.log_text.insert(tk.END, f"文件备份失败：{str(e)}\n")

    def upload_file(self, sftp, local_path, remote_path):
        try:
            sftp.put(local_path, remote_path)
            self.log_text.insert(tk.END, f"文件上传成功：{remote_path}\n")
        except Exception as e:
            self.log_text.insert(tk.END, f"文件上传失败：{str(e)}\n")

    def restart_project(self, sftp, hostname, username, password, remote_dir, jar_filename, log_keyword):
        try:
            script_path = "springboot.sh"
            target_path = f"./{jar_filename}"
            process_name = os.path.basename(target_path)  # 提取进程名称

            # 在远程服务器上执行命令
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname, port=22, username=username, password=password)

            # 获取进程 ID 并终止进程
            get_pid_command = f"pgrep -f {process_name}"  # 获取进程 ID
            stdin, stdout, stderr = ssh.exec_command(get_pid_command)
            process_id = stdout.read().decode('utf-8').strip()

            if process_id:
                kill_command = f"kill -9 {process_id}"  # 终止进程
                stdin, stdout, stderr = ssh.exec_command(kill_command)

                exit_status = stdout.channel.recv_exit_status()

                if exit_status == 0:
                    self.log_text.insert(tk.END, f"进程终止成功：{kill_command}\n")
                else:
                    self.log_text.insert(tk.END, f"进程终止失败，退出状态码：{exit_status}\n")
            else:
                self.log_text.insert(tk.END, "没有找到要终止的进程\n")

            # 执行启动命令
            start_command = f"cd {remote_dir} && ./{script_path} start {target_path}"
            stdin, stdout, stderr = ssh.exec_command(start_command)
            exit_status = stdout.channel.recv_exit_status()

            if exit_status == 0:
                self.log_text.insert(tk.END, f"启动命令执行成功：{start_command}\n")
            else:
                self.log_text.insert(tk.END, f"启动命令执行失败，退出状态码：{exit_status}\n")

            ssh.close()
        except Exception as e:
            self.log_text.insert(tk.END, f"重启命令执行失败：{str(e)}\n")

    def read_remote_file(self, sftp, remote_path):
        try:
            with sftp.file(remote_path, "r") as f:
                content = f.read().decode("utf-8")  # Specify encoding here
            return content
        except Exception as e:
            self.log_text.insert(tk.END, f"读取服务器文件失败：{str(e)}\n")
            return ""

    def read_local_file(self, local_path):
        try:
            with open(local_path, "r", encoding="utf-8") as f:
                content = f.read()
            return content
        except Exception as e:
            self.log_text.insert(tk.END, f"读取本地文件失败：{str(e)}\n")
            return ""

    def extract_datasource_config(self, existing_content):
        try:
            existing_yaml = yaml.safe_load(existing_content)
            datasource_config = existing_yaml.get('spring', {}).get('datasource', {})
            return datasource_config
        except yaml.YAMLError as e:
            self.log_text.insert(tk.END, f"解析旧的 spring.datasource 配置失败：{str(e)}\n")
            return {}

    def replace_datasource_config(self, new_content, datasource_config):
        try:
            new_yaml = yaml.safe_load(new_content)
            new_spring_config = new_yaml.get('spring', {})
            new_spring_config['datasource'] = datasource_config
            new_yaml['spring'] = new_spring_config

            updated_content = yaml.dump(new_yaml, default_flow_style=False)
            return updated_content
        except yaml.YAMLError as e:
            self.log_text.insert(tk.END, f"解析新的 spring.datasource 配置失败：{str(e)}\n")
            return new_content

    def write_remote_file(self, sftp, remote_path, content):
        try:
            with sftp.file(remote_path, "w") as f:
                f.write(content)
            self.log_text.insert(tk.END, "更新后的yml文件上传成功\n")
        except Exception as e:
            self.log_text.insert(tk.END, f"上传更新后的yml文件失败：{str(e)}\n")

    def add_spring_boot_script(self, sftp, remote_dir):
        script_name = "springboot.sh"
        local_script_path = os.path.join(os.path.dirname(__file__), script_name)
        remote_script_path = f"{remote_dir}/{script_name}"

        # Check if the script already exists on the server
        try:
            sftp.stat(remote_script_path)
        except FileNotFoundError:
            self.log_text.insert(tk.END, "正在上传 springboot.sh 文件...\n")
            sftp.put(local_script_path, remote_script_path)
            self.log_text.insert(tk.END, "springboot.sh 文件上传成功\n")


if __name__ == "__main__":
    root = tk.Tk()
    app = FileUploaderApp(root)
    root.mainloop()
