# SNMP Scanner

Agente SNMP desenvolvido em Python que realiza varreduras ARP na rede local e disponibiliza informações dos dispositivos encontrados por meio da MIB `SNMP-SCANNER-MIB`.

## Instalação

Instale as dependências:

```bash
pip install pysnmp==7.1.32 pysnmp-pysmi==6.0.1 scapy
```

## Preparar a MIB

Na raiz do projeto, compile a MIB:

```bash
mibdump --mib-source="file://$(realpath ./mibs)" \
  --destination-format=pysnmp \
  --destination-directory="$HOME/.pysnmp/mibs" \
  --rebuild SNMP-SCANNER-MIB
```

## Executar

Configure a sub-rede no arquivo `snmp-agent.py` e execute:

```bash
python snmp-agent.py
```

O agente utiliza o endereço `127.0.0.1`, porta `1161` e comunidade `public`.

![Inicialização do agente](images/image-9.png)

## Consultar

Consultar a sub-rede monitorada:

```bash
snmpget -v2c -c public 127.0.0.1:1161 1.3.6.1.3.99.1.2.0
```

![Consulta da sub-rede](images/image-3.png)

Consultar a quantidade de dispositivos:

```bash
snmpget -v2c -c public 127.0.0.1:1161 1.3.6.1.3.99.1.4.0
```

![Consulta da quantidade de dispositivos](images/image-4.png)

Listar os dispositivos e suas informações:

```bash
snmpwalk -v2c -c public 127.0.0.1:1161 1.3.6.1.3.99.2
```

![Consulta da tabela de dispositivos](images/image-10.png)

Limpar o histórico de dispositivos:

```bash
snmpset -v2c -c public 127.0.0.1:1161 1.3.6.1.3.99.1.5.0 i 1
```

![Limpeza do histórico](images/image-11.png)

## Alterações e justificativas da MIB

A MIB original, definida em SMIv1, foi revisada para SMIv2. As principais alterações foram:

- **MODULE-IDENTITY:** identificação formal do módulo, com informações de organização, contato e revisão.
- **MAX-ACCESS:** substituiu `ACCESS`, seguindo a sintaxe do SMIv2.
- **STATUS current:** substituiu `STATUS mandatory`, indicando que os objetos estão atualmente implementados.
- **Gauge32:** substituiu `Gauge` para representar a quantidade de dispositivos.
- **MacAddress:** textual convention utilizada para representar endereços MAC de seis octetos.
- **scannerClearHistory:** como SMIv2 não possui acesso `write-only`, o objeto foi definido como `read-write`, com os valores `clear(1)` e `idle(2)`. A leitura retorna `idle(2)`.
- **OBJECT-GROUP e MODULE-COMPLIANCE:** adicionados para organizar os objetos e declarar os requisitos de conformidade da MIB.

As alterações mantêm a finalidade original da MIB, adequando sua estrutura ao padrão SMIv2.

## Origem dos dados publicados

| Objeto | Origem dos dados |
|---|---|
| `scannerTimeout` | Valor constante de 5000 ms, utilizado na varredura ARP. |
| `scannerNetwork` | `Scanner.ip_rede`, sub-rede monitorada. |
| `scannerGateway` | `Scanner.gateway`, endereço do gateway padrão. |
| `scannerDeviceCount` | Quantidade de registros em `Scanner.historico_dispositivos`. |
| `scannerClearHistory` | Operação que limpa o histórico de dispositivos. |
| `scannerMacAddress` | `Device.mac`, também utilizado como índice da tabela. |
| `scannerIpAddress` | `Device.ip`, último endereço IP conhecido. |
| `scannerManufacturer` | `Device.fabricante`, obtido pela consulta à base OUI. |
| `scannerDeviceType` | `Device.tipo`, classificado como host ou router. |
| `scannerDeviceStatus` | `Device.status`, convertido para off, on ou returned. |
| `scannerReturnCountdown` | Valor de `Device.status`, limitado ao intervalo de 0 a 3. |
| `scannerDiscoveryTime` | `Device.descoberta`, data e hora da primeira descoberta. |

Os dados da tabela são atualizados conforme o scanner realiza novas varreduras e modifica o histórico de dispositivos.