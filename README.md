# 👻 Ghost Segurtasun Modulua
**PowerShell oinarritutako Windows eta Azure segurtasun gogortze tresna**

> **Windows amaiera puntuetarako eta Azure inguruneetarako segurtasun gogortze proaktiboa.** Ghost-ek beharrezkoak ez diren zerbitzuak eta protokoloak desgaituz eraso bektore ohikoak murrizteko lagun dezaketen PowerShell oinarritutako gogortze funtzioak eskaintzen ditu.

## ⚠️ Uko-egin Garrantzitsuak

**PROBAK BEHARREZKOAK**: Beti probatu Ghost ez-ekoizpen inguruneetan lehenik. Zerbitzuak desgaitzeak enpresa funtzio legitimoetan eragina izan dezake.

**EZ DAGO BERMERIK**: Ghost eraso bektore ohikoei zuzentzen zaien arren, ez da segurtasun tresna batek eraso guztiak saihestu dezakeenik. Hau segurtasun estrategia osoaren osagai bat da.

**ERAGINA ERAGIKETAN**: Funtzio batzuek sistemaren funtzionalitatean eragina izan dezakete. Aztertu ezarpen bakoitza arretaz hedatu aurretik.

**EBALUAZIO PROFESIONALA**: Ekoizpen inguruneetarako, kontsultatu segurtasun adituak ezarpenak zure erakundearen beharrizan egokitzen direla ziurtatzeko.

## 📊 Segurtasun Paisaia

Ransomware kalteak **2025ean 57 mila milioi dolarretara** iritsi ziren, ikerketak adierazten dutenez arrakasta duten eraso askok Windows oinarrizko zerbitzuak eta konfigurazio okerrak aprobetxatzen dituzte. Eraso bektore ohikoak hauek dira:

- **Ransomware gertaeren %90ak** RDP ustiapena dakarte
- **SMBv1 ahultasunek** WannaCry eta NotPetya bezalako erasoak ahalbidetu zituzten
- **Dokumentu makroek** malware banaketa metodo nagusi gisa jarraitzen dute
- **USB oinarritutako erasoek** aire-isolatutako sareetara zuzentzen jarraitzen dute
- **PowerShell abusua** azken urteetan nabarmen handitu da

## 🛡️ Ghost Segurtasun Funtzioak

Ghost-ek **16 Windows gogortze funtzio** eta **Azure segurtasun integrazioa** eskaintzen ditu:

### Windows Amaiera Puntu Gogortzea

| Funtzioa | Helburua | Kontuan hartzekoak |
|----------|----------|-------------------|
| `Set-RDP` | Urruneko mahaigain sarbidea kudeatzen du | Urruneko administrazioan eragina izan dezake |
| `Set-SMBv1` | Protokolo SMB zaharra kontrolatzen du | Sistema oso zaharretarako beharrezkoa |
| `Set-AutoRun` | AutoPlay/AutoRun kontrolatzen du | Erabiltzailearen erosotasunean eragina izan dezake |
| `Set-USBStorage` | USB biltegiratze gailuak murrizten ditu | USB erabilera legitimoan eragina izan dezake |
| `Set-Macros` | Office makro exekuzioa kontrolatzen du | Makro-gaitutako dokumentuetan eragina izan dezake |
| `Set-PSRemoting` | PowerShell urruneko konexioa kudeatzen du | Urruneko kudeaketan eragina izan dezake |
| `Set-WinRM` | Windows Urruneko Kudeaketa kontrolatzen du | Urruneko administrazioan eragina izan dezake |
| `Set-LLMNR` | Izen ebazpen protokoloa kudeatzen du | Normalean segurua da desgaitzeko |
| `Set-NetBIOS` | TCP/IP gaineko NetBIOS kontrolatzen du | Aplikazio zaharretan eragina izan dezake |
| `Set-AdminShares` | Administrazio partekatzeak kudeatzen ditu | Urruneko fitxategi sarbidean eragina izan dezake |
| `Set-Telemetry` | Datu bilketa kontrolatzen du | Diagnostiko gaitasunetan eragina izan dezake |
| `Set-GuestAccount` | Gonbidatu kontua kudeatzen du | Normalean segurua da desgaitzeko |
| `Set-ICMP` | Ping erantzunak kontrolatzen ditu | Sare diagnostikoan eragina izan dezake |
| `Set-RemoteAssistance` | Urruneko Laguntza kudeatzen du | Laguntza mahaiaren eragiketetan eragina izan dezake |
| `Set-NetworkDiscovery` | Sare aurkikuntza kontrolatzen du | Sare nabigatzailean eragina izan dezake |
| `Set-Firewall` | Windows Firewall kudeatzen du | Sare seguritatearentzat kritikoa da |

### Azure Hodei Segurtasuna

| Funtzioa | Helburua | Eskakizunak |
|----------|----------|-------------|
| `Set-AzureSecurityDefaults` | Azure AD oinarrizko segurtasuna gaitzen du | Microsoft Graph baimenak |
| `Set-AzureConditionalAccess` | Sarbide politikak konfiguratzen ditu | Azure AD P1/P2 lizentziak |
| `Set-AzurePrivilegedUsers` | Pribilegio kontuen auditoria egiten du | Global Admin baimenak |

### Enpresa Hedapen Aukerak

| Metodoa | Erabilera Kasua | Eskakizunak |
|---------|-----------------|-------------|
| **Zuzeneko Exekuzioa** | Probak, ingurune txikiak | Tokiko admin eskubideak |
| **Group Policy** | Domeinuko inguruneak | Domeinuko admin, GP kudeaketa |
| **Microsoft Intune** | Hodei-kudeatutako gailuak | Intune lizentziak, Graph API |

## 🚀 Hasiera Azkarra

### Segurtasun Ebaluazioa
```powershell
# Ghost modulua kargatu
IEX(Invoke-WebRequest 'https://raw.githubusercontent.com/jimrtyler/Ghost/main/Ghost.ps1')

# Oraingo segurtasun egoera egiaztatu
Get-Ghost
```

### Oinarrizko Gogortzea (Lehenik Probatu)
```powershell
# Funtsezko gogortzea - lehenik laborategiko ingurunean probatu
Set-Ghost -SMBv1 -AutoRun -Macros

# Aldaketak berrikusi
Get-Ghost
```

### Enpresa Hedapena
```powershell
# Group Policy hedapena (domeinuko inguruneak)
Set-Ghost -SMBv1 -AutoRun -GroupPolicy

# Intune hedapena (hodei-kudeatutako gailuak)
Set-Ghost -SMBv1 -RDP -USBStorage -Intune
```

## 📋 Instalazio Metodoak

### Aukera 1: Zuzeneko Deskarga (Probak)
```powershell
IEX(Invoke-WebRequest 'https://raw.githubusercontent.com/jimrtyler/Ghost/main/Ghost.ps1')
```

### Aukera 2: Modulu Instalazioa
```powershell
# PowerShell Gallery-tik instalatu (eskuragarri dagoenean)
Install-Module Ghost -Scope CurrentUser
Import-Module Ghost
```

### Aukera 3: Enpresa Hedapena
```powershell
# Sare kokapenera kopiatu Group Policy hedapenerako
# Intune PowerShell script-ak konfiguratu hodei hedapenerako
```

## 💼 Erabilera Kasuen Adibideak

### Negozio Txikia
```powershell
# Oinarrizko babesa eragin gutxiarekin
Set-Ghost -SMBv1 -AutoRun -Macros -ICMP
```

### Osasungintza Ingurunea
```powershell
# HIPAA-zentratu gogortzea
Set-Ghost -SMBv1 -RDP -USBStorage -AdminShares -Telemetry
```

### Finantza Zerbitzuak
```powershell
# Segurtasun handiko konfigurazioa
Set-Ghost -RDP -SMBv1 -AutoRun -USBStorage -Macros -PSRemoting -AdminShares
```

### Hodei-lehena Erakundea
```powershell
# Intune-kudeatutako hedapena
Connect-IntuneGhost -Interactive
Set-Ghost -SMBv1 -RDP -AutoRun -Macros -Intune
```

## 🔍 Funtzio Xehetasunak

### Oinarrizko Gogortze Funtzioak

#### Sare Zerbitzuak
- **RDP**: Urruneko mahaigain sarbidea blokeatzen du edo portua ausaztatzen du
- **SMBv1**: Fitxategi partekatzeko protokolo zaharra desgaitzen du
- **ICMP**: Erkaketa ping erantzunak saihesten ditu
- **LLMNR/NetBIOS**: Izen ebazpen protokolo zaharrak blokeatzen ditu

#### Aplikazio Segurtasuna
- **Makroak**: Office aplikazioetan makro exekuzioa desgaitzen du
- **AutoRun**: Euskarri kengarrietatik exekuzio automatikoa saihesten du

#### Urruneko Kudeaketa
- **PSRemoting**: PowerShell urruneko saioak desgaitzen ditu
- **WinRM**: Windows Urruneko Kudeaketa gelditzen du
- **Urruneko Laguntza**: Urruneko laguntza konexioak blokeatzen ditu

#### Sarbide Kontrola
- **Admin Partekatzeak**: C$, ADMIN$ partekatzeak desgaitzen ditu
- **Gonbidatu Kontua**: Gonbidatu kontu sarbidea desgaitzen du
- **USB Biltegiratzea**: USB gailu erabilera murrizten du

### Azure Integrazioa
```powershell
# Azure tenant-era konektatu
Connect-AzureGhost -Interactive

# Segurtasun lehenetsiak gaitu
Set-AzureSecurityDefaults -Enable

# Baldintza sarbidea konfiguratu
Set-AzureConditionalAccess -BlockLegacyAuth -RequireMFA

# Pribilegio erabiltzaileen auditoria egin
Set-AzurePrivilegedUsers -AuditOnly
```

### Intune Integrazioa (v2-ean berria)
```powershell
# Intune-ra konektatu
Connect-IntuneGhost -Interactive

# Intune politiken bidez hedatu
Set-IntuneGhost -Settings @{
    RDP = $true
    SMBv1 = $true
    USBStorage = $true
    Macros = $true
}
```

## ⚠️ Kontuan Hartzeko Garrantzitsuak

### Proba Eskakizunak
- **Laborategiko Ingurunea**: Ezarpen guztiak lehenik isolatutako ingurunean probatu
- **Faseka Hedapena**: Pixkanaka hedatu arazoak identifikatzeko
- **Atzera Botatzeko Plana**: Behar denean aldaketak itzul ditzakezula ziurtatu
- **Dokumentazioa**: Grabatu zure ingurunerako ezarpen bakoitzak funtzionatzen dutela

### Eragin Potentzialak
- **Erabiltzaile Produktibitatea**: Ezarpen batzuek eguneroko lan fluxuan eragina izan dezakete
- **Aplikazio Zaharrak**: Sistema zaharragoak protokolo jakin batzuk behar izan ditzakete
- **Urruneko Sarbidea**: Kontuan hartu urruneko administrazio legitimoan eragina
- **Negozio Prozesuak**: Egiaztatu ezarpenek ez dituztela funtzio kritikorik hausten

### Segurtasun Mugak
- **Sakonean Defentsa**: Ghost segurtasunaren geruza bat da, ez irtenbide osoa
- **Etengabeko Kudeaketa**: Segurtasunak etengabeko monitorizazioa eta eguneraketak behar ditu
- **Erabiltzaile Prestakuntza**: Kontrol teknikoak segurtasun kontzientziarekin lotu behar dira
- **Mehatxu Eboluzioa**: Eraso metodo berriek oraingo babesa gainditu dezakete

## 🎯 Eraso Agertoki Adibideak

Ghost eraso bektore ohikoei zuzentzen zaien arren, prebentzioa zehatz bat inplementazio eta proba egokirengan oinarritzen da:

### WannaCry-estiloko Erasoak
- **Arintzea**: `Set-Ghost -SMBv1` protokolo ahula desgaitzen du
- **Kontuan Hartzekoa**: Ziurtatu sistema zahar batek ere ez duela SMBv1 behar

### RDP oinarritutako Ransomware
- **Arintzea**: `Set-Ghost -RDP` urruneko mahaigain sarbidea blokeatzen du
- **Kontuan Hartzekoa**: Urruneko sarbide metodo alternatiboak behar izan ditzake

### Dokumentu oinarritutako Malware
- **Arintzea**: `Set-Ghost -Macros` makro exekuzioa desgaitzen du
- **Kontuan Hartzekoa**: Makro-gaitutako dokumentu legitimoetan eragina izan dezake

### USB bidez Banandutako Mehatxuak
- **Arintzea**: `Set-Ghost -USBStorage -AutoRun` USB funtzionalitatea murrizten du
- **Kontuan Hartzekoa**: USB gailu erabilera legitimoan eragina izan dezake

## 🏢 Enpresa Ezaugarriak

### Group Policy Laguntza
```powershell
# Ezarpenak Group Policy erregistroaren bidez aplikatu
Set-Ghost -SMBv1 -RDP -AutoRun -GroupPolicy

# Ezarpenak domeinuan zehar aplikatzen dira GP berrizketa ondoren
gpupdate /force
```

### Microsoft Intune Integrazioa
```powershell
# Ghost ezarpenentzat Intune politikak sortu
Set-IntuneGhost -Settings $GhostSettings -Interactive

# Politikak automatikoki hedatzen dira kudeatutako gailuetara
```

### Betetzeko Txostena
```powershell
# Segurtasun ebaluazio txostena sortu
Get-Ghost | Export-Csv -Path "SecurityAudit-$(Get-Date -Format 'yyyy-MM-dd').csv"

# Azure segurtasun egoera txostena
Get-AzureGhost | Out-File "AzureSecurityReport.txt"
```

## 📚 Praktika Onenak

### Aurreko Hedapena
1. **Oraingo Egoera Dokumentatu**: Aldaketen aurretik `Get-Ghost` exekutatu
2. **Sakonki Probatu**: Ez-ekoizpen ingurunean baliozkotu
3. **Atzera Botatzeko Plana**: Jakin nola ezarpen bakoitza itzuli
4. **Interesdun Berrikuspenak**: Ziurtatu negozio unitateek aldaketak onartzen dituztela

### Hedapen Bitartean
1. **Faseka Ikuspegia**: Lehenik pilotu taldeetan hedatu
2. **Eragina Monitorizatu**: Erabiltzaile kexak edo sistema arazoak begiratu
3. **Arazoak Dokumentatu**: Etorkizuneko erreferentziarako edozein arazo grabatu
4. **Aldaketak Komunikatu**: Erabiltzaileak segurtasun hobekuntzei buruz informatu

### Hedapen Ondoren
1. **Aldizka Ebaluazioa**: Aldizkka `Get-Ghost` exekutatu ezarpenak egiaztatzeko
2. **Dokumentazioa Eguneratu**: Segurtasun konfigurazioak egunean mantendu
3. **Eraginkortasuna Berrikusi**: Segurtasun gertakarien monitorizazioa egin
4. **Etengabeko Hobekuntza**: Mehatxu paisaiaren arabera ezarpenak doitu

## 🔧 Arazo Konponketa

### Arazo Ohikoak
- **Baimen Erroreak**: Ziurtatu PowerShell saio igotakoa dela
- **Zerbitzu Mendekotasunak**: Zerbitzu batzuek mendekotasunak izan ditzakete
- **Aplikazio Bateragarritasuna**: Negozio aplikazioekin probatu
- **Sare Konektibitatea**: Egiaztatu urruneko sarbideak oraindik funtzionatzen duela

### Berreskuratze Aukerak
```powershell
# Behar denean zerbitzu zehatzak berriro gaitu
Set-RDP -Enable
Set-SMBv1 -Enable
Set-AutoRun -Enable
Set-Macros -Enable
```

## 👨‍💻 Egileari Buruz

**Jim Tyler** - PowerShell-erako Microsoft MVP
- **YouTube**: [@PowerShellEngineer](https://youtube.com/@PowerShellEngineer) (10.000+ harpidedun)
- **Buletina**: [PowerShell.News](https://powershell.news) - Asteko segurtasun informazioa
- **Egilea**: "PowerShell for Systems Engineers"
- **Esperientzia**: PowerShell automatizazio eta Windows segurtasunaren hamarkadak

## 📄 Lizentzia eta Uko-egitea

### MIT Lizentzia
Ghost dohainik erabiltzeko, aldatzeko eta banatzeko MIT Lizentzian eskaintzen da.

### Segurtasun Uko-egitea
- **Ez Dago Bermerik**: Ghost "dagoen bezala" eskaintzen da inongo motatako bermerik gabe
- **Probak Beharrezkoak**: Beti probatu ez-ekoizpen inguruneetan lehenik
- **Gidatze Profesionala**: Ekoizpen hedapenetarako segurtasun adituak kontsultatu
- **Eragiketa Eragina**: Egileak ez dira erantzule edozein eragiketa eteterik
- **Segurtasun Integrala**: Ghost segurtasun estrategia osoaren osagai bat da

### Laguntza
- **GitHub Arazoak**: [Akatsak salatu edo ezaugarriak eskatu](https://github.com/jimrtyler/Ghost/issues)
- **Dokumentazioa**: Laguntza xehaturako `Get-Help <function> -Full` erabili
- **Komunitatea**: PowerShell eta segurtasun komunitateko foroak

---

**🔐 Sendotu zure segurtasun egoera Ghost-ekin - baina beti probatu lehenik.**

```powershell
# Hasi ebaluazioarekin, ez suposizioetan
Get-Ghost
```

**⭐ Eman izar bat errepositorio honi Ghost-ek zure segurtasun egoera hobetzen laguntzen badu!**