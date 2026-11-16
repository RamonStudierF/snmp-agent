import threading
import time
from pathlib import Path
from scanner import Scanner
from pysnmp.entity import engine
from pysnmp.entity.rfc3413 import context
from pysnmp.smi import builder
from pysnmp.entity import config
from pysnmp.entity.rfc3413 import cmdrsp
from pysnmp.carrier.asyncio.dgram import udp



snmpEngine = engine.SnmpEngine()
snmpContext = context.SnmpContext(snmpEngine)

mibBuilder = snmpContext.get_mib_instrum().get_mib_builder()

# Diretório onde o mibdump gerou os módulos Python
MIB_COMPILED_DIR = Path.home() / ".pysnmp" / "mibs"

# Adiciona o diretório às fontes de MIB
mibBuilder.add_mib_sources(
    builder.DirMibSource(str(MIB_COMPILED_DIR))
)

# Carrega sua MIB já compilada
mibBuilder.load_modules("SNMP-SCANNER-MIB")

(MibScalarInstance,) = mibBuilder.import_symbols(
    "SNMPv2-SMI",
    "MibScalarInstance"
)

(scannerTimeout,) = mibBuilder.import_symbols(
    "SNMP-SCANNER-MIB",
    "scannerTimeout"
)



class ScannerInstance(MibScalarInstance):

    def __init__(self, name, instance_id, syntax, getter, initial_value, on_set=None):
        super().__init__(
            name,
            instance_id,
            syntax.clone(initial_value)
        )
        self.getter = getter
        self.on_set = on_set

    def getValue(self, name, **context):
        return self.getSyntax().clone(self.getter())

    def setValue(self, value, name, **context):
        if self.on_set is None:
            return super().setValue(value, name, **context)

        self.pending_value = self.getSyntax().clone(value)
        return self.getSyntax().clone(self.getter())

    def writeCommit(self, varBind, **context):
        super().writeCommit(varBind, **context)

        if self.pending_value is not None:
            valor = self.pending_value
            self.pending_value = None
            self.on_set(valor)
    def writeCleanup(self, varBind, **context):
        super().writeCleanup(varBind, **context)
        self.pending_value = None

    def writeUndo(self, varBind, **context):
        super().writeUndo(varBind, **context)
        self.pending_value = None
    
(
    scannerTimeout,
    scannerNetwork,
    scannerGateway,
    scannerDeviceCount,
    scannerClearHistory
) = mibBuilder.import_symbols(
    "SNMP-SCANNER-MIB",
    "scannerTimeout",
    "scannerNetwork",
    "scannerGateway",
    "scannerDeviceCount",
    "scannerClearHistory"
)

(
    scannerResultEntry,
    scannerMacAddress,
    scannerIpAddress,
    scannerManufacturer,
    scannerDeviceType,
    scannerDeviceStatus,
    scannerReturnCountdown,
    scannerDiscoveryTime,
) = mibBuilder.import_symbols(
    "SNMP-SCANNER-MIB",
    "scannerResultEntry",
    "scannerMacAddress",
    "scannerIpAddress",
    "scannerManufacturer",
    "scannerDeviceType",
    "scannerDeviceStatus",
    "scannerReturnCountdown",
    "scannerDiscoveryTime",
)

# Normaliza os valores de MAX-ACCESS gerados pelo PySMI
access_mapping = {
    "readonly": "read-only",
    "readwrite": "read-write",
    "readcreate": "read-create",
    "notaccessible": "not-accessible"
}

objetos_mib = [
    scannerTimeout,
    scannerNetwork,
    scannerGateway,
    scannerDeviceCount,
    scannerClearHistory,

    scannerMacAddress,
    scannerIpAddress,
    scannerManufacturer,
    scannerDeviceType,
    scannerDeviceStatus,
    scannerReturnCountdown,
    scannerDiscoveryTime,
]

for objeto in objetos_mib:
    acesso_antigo = objeto.getMaxAccess()
    acesso_novo = access_mapping.get(acesso_antigo, acesso_antigo)

    objeto.setMaxAccess(acesso_novo)

scanner = Scanner(ip_rede="192.168.0.0/24")

mibBuilder.export_symbols(
    "__SNMP-SCANNER-AGENT",

    scannerTimeoutInstance=ScannerInstance(
        scannerTimeout.name,
        (0,),
        scannerTimeout.syntax,
        lambda: 5000,
        5000,
        on_set=None


    ),

    scannerNetworkInstance=ScannerInstance(
        scannerNetwork.name,
        (0,),
        scannerNetwork.syntax,
        lambda: scanner.ip_rede or "",
        scanner.ip_rede or "",
        on_set=lambda valor: setattr(
            scanner, "ip_rede", valor.prettyPrint()
        )

    ),

    scannerGatewayInstance=ScannerInstance(
        scannerGateway.name,
        (0,),
        scannerGateway.syntax,
        lambda: scanner.gateway or "0.0.0.0",
        scanner.gateway or "0.0.0.0",
        on_set=None

    ),

    scannerDeviceCountInstance=ScannerInstance(
        scannerDeviceCount.name,
        (0,),
        scannerDeviceCount.syntax,
        lambda: len(scanner.historico_dispositivos),
        0,
        on_set=None

    ),

    scannerClearHistoryInstance=ScannerInstance(
        scannerClearHistory.name,
        (0,),
        scannerClearHistory.syntax,
        lambda: 2,
        2,
        on_set=lambda valor: limpar_historico() if int(valor) == 1 else None
    ),
)

linhas_registradas = set()

def registrar_dispositivos():

    colunas = [
        (
            "scannerMacAddress",
            scannerMacAddress,
            lambda d: bytes.fromhex(d.mac.replace(":", ""))
        ),
        (
            "scannerIpAddress",
            scannerIpAddress,
            lambda d: d.ip
        ),
        (
            "scannerManufacturer",
            scannerManufacturer,
            lambda d: d.fabricante
        ),
        (
            "scannerDeviceType",
            scannerDeviceType,
            lambda d: 2 if d.tipo.lower() == "router" else 1
        ),
        (
            "scannerDeviceStatus",
            scannerDeviceStatus,
            lambda d: 1 if d.status == -1 else (2 if d.status == 0 else 3)
        ),
        (
            "scannerReturnCountdown",
            scannerReturnCountdown,
            lambda d: min(max(d.status, 0), 3)
        ),
        (
            "scannerDiscoveryTime",
            scannerDiscoveryTime,
            lambda d: d.descoberta.strftime("%Y-%m-%d %H:%M:%S")
        ),
    ]

    for mac in list(scanner.historico_dispositivos):

        if mac in linhas_registradas:
            continue

        mac_bytes = bytes.fromhex(mac.replace(":", ""))

        # Gera o índice da linha com base no MAC
        indice = scannerResultEntry.getInstIdFromIndices(mac_bytes)

        instancias = {}

        for nome, coluna, conversor in colunas:

            # O getter consulta o dispositivo no histórico
            getter = lambda m=mac, conv=conversor: conv(
                scanner.historico_dispositivos[m]
            )

            initial_value = getter()

            instancia = ScannerInstance(
                coluna.name,
                indice,
                coluna.syntax,
                getter,
                initial_value,
                on_set=None
            )

            simbolo = f"{nome}_{mac.replace(':', '')}"

            instancias[simbolo] = instancia

        # Registra todas as colunas da linha na MIB
        mibBuilder.export_symbols(
            "__SNMP-SCANNER-ROWS",
            **instancias
        )

        linhas_registradas.add(mac)

def limpar_historico():
    colunas = [
        "scannerMacAddress",
        "scannerIpAddress",
        "scannerManufacturer",
        "scannerDeviceType",
        "scannerDeviceStatus",
        "scannerReturnCountdown",
        "scannerDiscoveryTime"
    ]

    simbolos = [
        f"{coluna}_{mac.replace(':', '')}"
        for mac in linhas_registradas
        for coluna in colunas
    ]

    if simbolos:
        mibBuilder.unexport_symbols(
            "__SNMP-SCANNER-ROWS",
            *simbolos
        )

    scanner.historico_dispositivos.clear()
    linhas_registradas.clear()

    print("[SNMP] Histórico de dispositivos limpo.")


config.add_transport(
    snmpEngine,
    udp.DOMAIN_NAME,
    udp.UdpTransport().open_server_mode(("127.0.0.1", 1161))
)

config.add_v1_system(
    snmpEngine,
    "scanner-area",
    "public",
    securityName="scanner-area"
)

config.add_vacm_user(
    snmpEngine,
    2,
    "scanner-area",
    "noAuthNoPriv",
    readSubTree=(1, 3, 6, 1, 3, 99),
    writeSubTree=(1, 3, 6, 1, 3, 99)
)

cmdrsp.GetCommandResponder(snmpEngine, snmpContext)
cmdrsp.NextCommandResponder(snmpEngine, snmpContext)
cmdrsp.BulkCommandResponder(snmpEngine, snmpContext)
cmdrsp.SetCommandResponder(snmpEngine, snmpContext)

def monitorar():

    while True:

        inicio = time.monotonic()

        dispositivos = scanner.scan()

        scanner.gerencia_devices(dispositivos)

        # Registra os novos dispositivos encontrados
        registrar_dispositivos()

        scanner.imprimir_relatorio()

        tempo_decorrido = time.monotonic() - inicio

        time.sleep(max(0, 4 - tempo_decorrido))

threading.Thread(
    target=monitorar,
    daemon=True
).start()

snmpEngine.transport_dispatcher.job_started(1)

try:
    snmpEngine.open_dispatcher()
except Exception:
    snmpEngine.close_dispatcher()
    raise