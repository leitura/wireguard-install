# Instalador WireGuard


**Este projeto é um script bash que visa configurar um [WireGuard](https://www.wireguard.com/) VPN em um servidor Linux, tão facilmente quanto possível!**

O WireGuard é uma VPN ponto a ponto que pode ser usada de diferentes maneiras. Aqui, queremos dizer uma VPN como em: o cliente irá encaminhar todo o seu tráfego através de um túnel criptografado para o servidor.
O servidor aplicará o NAT ao tráfego do cliente para que pareça que o cliente está navegando na web com o IP do servidor.

O script oferece suporte a IPv4 e IPv6. Por favor, cheque o [issues](https://github.com/leitura/wireguard-install/issues) para desenvolvimento contínuo, bugs e recursos planejados!

WireGuard does not fit your environment? Check out [openvpn-install](https://github.com/leitura/openvpn-install).

## Requisitos

Distribuições com suporte:

- Ubuntu >= 16.04
- Debian >= 10
- Fedora
- CentOS
- Arch Linux
- Oracle Linux

## Use

Baixe e execute o script. Responda às perguntas do roteiro e ele cuidará do resto.

```bash
curl -O https://raw.githubusercontent.com/leitura/wireguard-install/master/wireguard-install.sh
chmod +x wireguard-install.sh
./wireguard-install.sh
```

Ele irá instalar o WireGuard (módulo do kernel e ferramentas) no servidor, configurá-lo, criar um serviço systemd e um arquivo de configuração do cliente.

Execute o script novamente para adicionar ou remover clientes!