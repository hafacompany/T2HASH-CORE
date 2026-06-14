rm -f install.sh
cat << 'EOF' > install.sh
#!/bin/bash


clear

RED='\033[38;5;196m'
PINK='\033[38;5;198m'
DARK='\033[38;5;236m'
GREY='\033[38;5;245m'
WHITE='\033[1;37m'
RESET='\033[0m'

echo -e "${RED}"
echo "  ▄▄▄█████▓ ▀████▄     ▄▄▄█████▓ ██░ ██  ▄▄▄       ██████  ██░ ██ "
echo "  ▓  ██▒ ▓▒   ██▀ ▀█   ▓  ██▒ ▓▒▓██░ ██▒▒████▄   ▒██    ▒ ▓██░ ██▒"
echo "  ▒ ▓██░ ▒░  ██   ▄▄▄  ▒ ▓██░ ▒░▒██▀▀██░▒██  ▀█▄ ░ ▓██▄   ▒██▀▀██░"
echo "  ░ ▓██▓ ░   ██▄▄▄██   ░ ▓██▓ ░ ░▓█ ░██ ░██▄▄▄▄██  ▒   ██▒░▓█ ░██ "
echo "    ▒██▒ ░    ▀▀▀▀██▒    ▒██▒ ░ ░▓█▒░██▓ ▓█   ▓██▒▒██████▒▒░▓█▒░██▓"
echo "    ▒ ░░      ░   ▒▒     ▒ ░░    ▒ ░░▒░▒ ▒▒   ▓▒█░▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒"
echo "      ░       ░   ▒        ░     ▒ ░▒░ ░  ▒   ▒▒ ░░ ░▒  ░ ░ ▒ ░▒░ ░"
echo "    ░             ░      ░       ░  ░░ ░  ░   ▒   ░  ░  ░   ░  ░░ ░"
echo -e "${RESET}"
echo -e "      ${DARK}======================================================${RESET}"
echo -e "                ${PINK}Created by T2HASH, Layer-0 Assembly${RESET}"
echo -e "      ${DARK}======================================================${RESET}"
echo ""
echo -e "             ${WHITE}[ 1 ] ${GREY}Server Kharej (Hetzner / Receiver)${RESET}"
echo -e "             ${WHITE}[ 2 ] ${GREY}Server Iran (Sender)${RESET}"
echo ""
echo -e "      ${DARK}------------------------------------------------------${RESET}"
echo -ne "      ${PINK}root@t2hash${WHITE}:~#${RESET} Koodom server ro dari config mikoni? [1 ya 2]: "
read RAW_TYPE

SERVER_TYPE=$(echo "$RAW_TYPE" | tr -d '\r' | tr -d ' ' | tr -d '\n')

if [ "$SERVER_TYPE" == "2" ]; then
    echo ""
    echo -ne "      ${PINK}root@t2hash${WHITE}:~#${RESET} IP Server Kharej ro vared kon: "
    read RAW_IP
    OUT_IP=$(echo "$RAW_IP" | tr -d '\r' | tr -d ' ' | tr -d '\n')
    IFS='.' read -r i1 i2 i3 i4 <<< "$OUT_IP"
    HEX_IP=$(printf "0x%02X, 0x%02X, 0x%02X, 0x%02X" $i1 $i2 $i3 $i4)
    echo -e "      ${DARK}[+]${RESET} IP be Hex tabdil shod: ${PINK}${HEX_IP}${RESET}"
fi

echo ""
echo -e "      ${DARK}------------------------------------------------------${RESET}"
echo -e "      ${RED}[1/5]${RESET} ${GREY}Pak kardan nuskhe haye ghabli...${RESET}"
systemctl stop asm-hz gost-hz asm-ir gost-ir 2>/dev/null
systemctl disable asm-hz gost-hz asm-ir gost-ir 2>/dev/null
rm -f /etc/systemd/system/asm-hz.service /etc/systemd/system/gost-hz.service /etc/systemd/system/asm-ir.service /etc/systemd/system/gost-ir.service
rm -f /root/asm_udp_* 2>/dev/null
systemctl daemon-reload

echo -e "      ${RED}[2/5]${RESET} ${GREY}Nasb pish-niaz ha (Nasm, Build tools)...${RESET}"
apt update -qq && apt install nasm build-essential wget gzip -y > /dev/null 2>&1

echo -e "      ${RED}[3/5]${RESET} ${GREY}Sakht ASM TUN FILE.....${RESET}"
if [ ! -f /usr/local/bin/gost ]; then
    wget -q https://github.com/ginuerzh/gost/releases/download/v2.11.5/gost-linux-amd64-2.11.5.gz -O /tmp/gost.gz
    gzip -d /tmp/gost.gz
    chmod +x /tmp/gost
    mv /tmp/gost /usr/local/bin/gost
fi

echo -e "      ${RED}[4/5]${RESET} ${GREY}Behin-sazi Buffer shabake (Zede Packet-Loss)...${RESET}"
sysctl -w net.core.rmem_max=26214400 >/dev/null
sysctl -w net.core.rmem_default=26214400 >/dev/null
sysctl -w net.core.wmem_max=26214400 >/dev/null
sysctl -w net.core.wmem_default=26214400 >/dev/null

echo -e "      ${RED}[5/5]${RESET} ${GREY}Sakht Code Assembly va Service ha...${RESET}"

if [ "$SERVER_TYPE" == "1" ]; then
    # ================== SERVER KHAREJ ==================
    cat << 'IN_EOF' > /root/asm_udp_hz.asm
section .data
    bind_addr db 2, 0, 0x01, 0xBB, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    gost_addr db 2, 0, 0x04, 0x38, 0x7F, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0
    peer_len dq 16
section .bss
    fd resq 1
    buffer resb 4096
    ir_addr resb 16
    peer_addr resb 16
section .text
    global _start
_start:
    mov rax, 41
    mov rdi, 2
    mov rsi, 2
    mov rdx, 0
    syscall
    mov [fd], rax
    mov rax, 49
    mov rdi, [fd]
    mov rsi, bind_addr
    mov rdx, 16
    syscall
.loop:
    mov rax, 45
    mov rdi, [fd]
    mov rsi, buffer
    mov rdx, 4096
    mov r10, 0
    mov r8, peer_addr
    mov r9, peer_len
    mov qword [peer_len], 16
    syscall
    cmp rax, 0
    jle .loop
    mov r12, rax
    mov rcx, 0
.xor_loop:
    mov al, [buffer + rcx]
    xor al, 0x5A
    mov [buffer + rcx], al
    inc rcx
    cmp rcx, r12
    jl .xor_loop
    mov eax, dword [peer_addr + 4]
    cmp eax, 0x0100007F
    je .from_gost
.from_ir:
    mov rax, qword [peer_addr]
    mov qword [ir_addr], rax
    mov rax, qword [peer_addr + 8]
    mov qword [ir_addr + 8], rax
    mov rax, 44
    mov rdi, [fd]
    mov rsi, buffer
    mov rdx, r12
    mov r10, 0
    mov r8, gost_addr
    mov r9, 16
    syscall
    jmp .loop
.from_gost:
    mov rax, 44
    mov rdi, [fd]
    mov rsi, buffer
    mov rdx, r12
    mov r10, 0
    mov r8, ir_addr
    mov r9, 16
    syscall
    jmp .loop
IN_EOF

    nasm -f elf64 /root/asm_udp_hz.asm -o /root/asm_udp_hz.o && ld /root/asm_udp_hz.o -o /root/asm_udp_hz

    cat << 'IN_EOF' > /etc/systemd/system/asm-hz.service
[Unit]
Description=Assembly UDP Receiver
After=network.target
[Service]
Type=simple
ExecStart=/root/asm_udp_hz
Restart=always
[Install]
WantedBy=multi-user.target
IN_EOF

    cat << 'IN_EOF' > /etc/systemd/system/gost-hz.service
[Unit]
Description=Gost KCP Stealth Receiver
After=network.target
[Service]
Type=simple
ExecStart=/usr/local/bin/gost -L "kcp://127.0.0.1:1080?mode=normal&mtu=1350&nocomp=true&smux=true"
Restart=always
[Install]
WantedBy=multi-user.target
IN_EOF

    systemctl daemon-reload
    systemctl enable --now asm-hz gost-hz
    echo ""
    echo -e "      ${PINK}✅ NASB KAMEL SHOD! Server Kharej rooye port 443 amade ast.${RESET}"
    echo ""

elif [ "$SERVER_TYPE" == "2" ]; then
    # ================== SERVER IRAN ==================
    cat << IN_EOF > /root/asm_udp_ir.asm
section .data
    bind_addr db 2, 0, 0x1E, 0x61, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    hz_addr db 2, 0, 0x01, 0xBB, ${HEX_IP}, 0, 0, 0, 0, 0, 0, 0, 0
    peer_len dq 16
section .bss
    fd resq 1
    buffer resb 4096
    gost_addr resb 16
    peer_addr resb 16
section .text
    global _start
_start:
    mov rax, 41
    mov rdi, 2
    mov rsi, 2
    mov rdx, 0
    syscall
    mov [fd], rax
    mov rax, 49
    mov rdi, [fd]
    mov rsi, bind_addr
    mov rdx, 16
    syscall
.loop:
    mov rax, 45
    mov rdi, [fd]
    mov rsi, buffer
    mov rdx, 4096
    mov r10, 0
    mov r8, peer_addr
    mov r9, peer_len
    mov qword [peer_len], 16
    syscall
    cmp rax, 0
    jle .loop
    mov r12, rax
    mov rcx, 0
.xor_loop:
    mov al, [buffer + rcx]
    xor al, 0x5A
    mov [buffer + rcx], al
    inc rcx
    cmp rcx, r12
    jl .xor_loop
    mov eax, dword [peer_addr + 4]
    cmp eax, 0x0100007F
    jne .from_hz
.from_client:
    mov rax, qword [peer_addr]
    mov qword [gost_addr], rax
    mov rax, qword [peer_addr + 8]
    mov qword [gost_addr + 8], rax
    mov rax, 44
    mov rdi, [fd]
    mov rsi, buffer
    mov rdx, r12
    mov r10, 0
    mov r8, hz_addr
    mov r9, 16
    syscall
    jmp .loop
.from_hz:
    mov rax, 44
    mov rdi, [fd]
    mov rsi, buffer
    mov rdx, r12
    mov r10, 0
    mov r8, gost_addr
    mov r9, 16
    syscall
    jmp .loop
IN_EOF

    nasm -f elf64 /root/asm_udp_ir.asm -o /root/asm_udp_ir.o && ld /root/asm_udp_ir.o -o /root/asm_udp_ir

    cat << 'IN_EOF' > /etc/systemd/system/asm-ir.service
[Unit]
Description=Assembly UDP Sender
After=network.target
[Service]
Type=simple
ExecStart=/root/asm_udp_ir
Restart=always
[Install]
WantedBy=multi-user.target
IN_EOF

    cat << 'IN_EOF' > /etc/systemd/system/gost-ir.service
[Unit]
Description=Gost KCP Stealth Sender
After=network.target
[Service]
Type=simple
ExecStart=/usr/local/bin/gost -L socks5://:8081 -F "kcp://127.0.0.1:7777?mode=normal&mtu=1350&nocomp=true&smux=true"
Restart=always
[Install]
WantedBy=multi-user.target
IN_EOF

    systemctl daemon-reload
    systemctl enable --now asm-ir gost-ir
    echo ""
    echo -e "      ${PINK}✅ NASB KAMEL SHOD! Server Iran amade ast. Ba kood 8081 (Socks5) vasl sho.${RESET}"
    echo ""
else
    echo -e "      ${RED}[!] Entekhab eshtebah bood! Dobare ejra kon.${RESET}"
fi
EOF
chmod +x install.sh

