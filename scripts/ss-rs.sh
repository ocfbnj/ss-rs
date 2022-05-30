#!/bin/sh

name="ss-rs"

ss_remote_start_file="/etc/${name}/remote.sh"
ss_remote_log_file="/var/log/${name}/remote.log"
ss_remote_service_name="ss-remote.service"
ss_remote_service_file="/etc/systemd/system/${ss_remote_service_name}"

default_port="8000"
default_password="ss-rs-remote"

acme_directory="${HOME}/.acme.sh"
acme_file="${acme_directory}/acme.sh"

echo -n "Please enter your email: "
read email

echo -n "Please enter your domain name: "
read domain_name

# 1. Install cargo.
if ! command -v cargo; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    export PATH="$HOME/.cargo/bin:$PATH"
else
    echo "You have already installed cargo"
fi

# 2. Install ss-rs.
if ! command -v ss-rs; then
    cargo install ${name}
else
    echo "You have already installed ss-rs"
fi

# 3. Install v2ray-plugin
if ! command -v v2ray-plugin; then
    mkdir -p /usr/local/bin
    version="v1.3.1"
    file_name="v2ray-plugin-linux-amd64-${version}.tar.gz"
    wget https://github.com/shadowsocks/v2ray-plugin/releases/download/${version}/${file_name}
    tar -xzf ${file_name}
    mv ./v2ray-plugin_linux_amd64 /usr/local/bin/v2ray-plugin
    rm ${file_name}
else
    echo "You have already installed v2ray-plugin"
fi

# 4. Install socat.
if ! command -v socat; then
    apt-get update
    apt-get install socat -y
else
    echo "You have already installed nginx"
fi

# 5. Install acme.
if ! test -f ${acme_file}; then
    curl https://get.acme.sh | sh -s email=${email}
else
    echo "File ${acme_file} exists"
fi

# 6. Generate certificate.
if ! test -d "${acme_directory}/${domain_name}"; then
    ${acme_file} --issue -d ${domain_name} --standalone
else
    echo "Directory ${acme_directory}/${domain_name} exists"
fi

# 7. Create directories.
if ! test -d "/etc/${name}"; then
    mkdir -p "/etc/${name}"
else
    echo "Directory /etc/${name} exists"
fi

if ! test -d "/var/log/${name}"; then
    mkdir -p "/var/log/${name}"
else
    echo "Directory /var/log/${name} exists"
fi

# 8. Create startup script.
if ! test -f ${ss_remote_start_file}; then
    cat <<EOF > ${ss_remote_start_file}
#!/bin/bash
${HOME}/.cargo/bin/${name} -s 0.0.0.0:${default_port} -k ${default_password} --plugin v2ray-plugin --plugin-opts "server;tls;host=${domain_name}" 2>> ${ss_remote_log_file} &
EOF

    chmod ug+x ${ss_remote_start_file}
else
    echo "File ${ss_remote_start_file} exists"
fi

# 9. Create service.
if ! test -f ${ss_remote_service_file}; then
    cat <<EOF > ${ss_remote_service_file}
[Unit]
Description=${name} remote server
After=network.target

[Service]
Type=forking
ExecStart=${ss_remote_start_file}

[Install]
WantedBy=default.target
EOF
else
    echo "File ${ss_remote_service_file} exists"
fi

# 10. Start service.
systemctl daemon-reload
systemctl enable --now ${ss_remote_service_name}

# 11. Done
echo "== Done =="
