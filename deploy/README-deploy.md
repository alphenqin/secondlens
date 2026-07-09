# secondlens 服务器部署

部署方式：服务器从 Git 拉代码，本机把未提交到 Git 的运行密钥和证书目录 `secret/` 上传到服务器项目根目录。

## 1. 准备服务器目录

```bash
sudo mkdir -p /opt/secondlens
sudo chown -R "$USER":"$USER" /opt/secondlens
git clone <repo-url> /opt/secondlens
cd /opt/secondlens
```

如果服务器上已经有仓库：

```bash
cd /opt/secondlens
git pull
```

## 2. 上传密钥和证书

在开发机执行：

```bash
rsync -av secret/ <server>:/opt/secondlens/secret/
```

上传后服务器应存在：

```text
/opt/secondlens/secret/360-aksk.txt
/opt/secondlens/secret/wfy-root-ca.pem
```

IntelLens 配置已经纳入项目目录 `config/intellens/`，会随 Git 一起部署。

## 3. 安装依赖

```bash
cd /opt/secondlens
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

## 4. 检查配置

启动服务前，按目标环境修改 `/opt/secondlens/config.yaml`。

重点字段：

```yaml
storage:
  env: prod
  aksk_file: secret/360-aksk.txt
  ca_file: secret/wfy-root-ca.pem

runtime:
  upload: true
```

只有需要使用测试桶时才保留 `env: dev`。

## 5. 安装 systemd 服务

如果项目不是放在 `/opt/secondlens`，先修改 `deploy/secondlens.service` 里的两个 `/opt/secondlens` 路径。

```bash
sudo cp deploy/secondlens.service /etc/systemd/system/secondlens.service
sudo systemctl daemon-reload
sudo systemctl enable --now secondlens
sudo systemctl status secondlens
```

查看日志：

```bash
journalctl -u secondlens -f
tail -f /opt/secondlens/logs/secondlens.log
```

## 6. 前台冒烟测试

需要先验证时，可以在启用 systemd 前跑一次：

```bash
cd /opt/secondlens
. .venv/bin/activate
INTELLENS_CONFIG=/opt/secondlens/config/intellens/prod.yaml python main.py bucket --max-tasks 1
```
