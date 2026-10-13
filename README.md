# Integrazione Custom Home Assistant: BTicino HOMETOUCH (Art. 3488)

Integrazione locale per Home Assistant dedicata al videocitofono/pannello **BTicino HOMETOUCH (3488 / 3488W)** e impianti MyHOME connessi che utilizzano l'app *Door Entry for Hometouch*.

Permette di:
- 🚪 **Aprire il Portoncino** (entità `lock.portoncino` e `button.apri_portoncino`).
- ⛩️ **Aprire il Cancello** (entità `button.apri_cancello`).
- 💡 **Accendere le Luci Scale** (entità `button.luce_scale`).
- 🔔 **Rilevare la suonata del campanello** in tempo reale (entità `binary_sensor.campanello_chiamata`).
- 📹 **Visualizzare il flusso videocitofonico** (entità `camera.videocitofono`).

---

## 📦 Installazione in Home Assistant

1. Copia la cartella `custom_components/bticino_hometouch` all'interno della directory `config/custom_components/` della tua installazione di Home Assistant:
   ```text
   /config/
     └── custom_components/
           └── bticino_hometouch/
                 ├── __init__.py
                 ├── manifest.json
                 ├── const.py
                 ├── client.py
                 ├── config_flow.py
                 ├── lock.py
                 ├── button.py
                 ├── binary_sensor.py
                 ├── camera.py
                 ├── strings.json
                 └── translations/
                       ├── it.json
                       └── en.json
   ```
2. Riavvia Home Assistant (**Strumenti per sviluppatori** -> **Riavvia**).
3. Vai su **Impostazioni** -> **Dispositivi e Servizi** -> **Aggiungi Integrazione**.
4. Cerca **BTicino HOMETOUCH**.
5. Inserisci l'**Indirizzo IP** locale del tuo pannello Hometouch (es. `192.168.1.120`).

---

## ⚙️ Parametri di Configurazione

| Parametro | Descrizione | Valore Predefinito |
| :--- | :--- | :--- |
| **Indirizzo IP** | Indirizzo IP locale del pannello HOMETOUCH | *Obbligatorio* |
| **Porta** | Porta OpenWebNet TCP | `20000` |
| **Password OpenWebNet** | Password OpenWebNet (se impostata sull'Hometouch) | *(Nessuna)* |
| **Indirizzo Portoncino** | Numero/indirizzo del posto esterno principale | `4` |
| **Indirizzo Cancello** | Numero/indirizzo dell'attuatore o relè cancello | `4` |
| **Tipo Comando Cancello** | `2009` (Relè ausiliario cancello) o `10060` (Serratura 2) | `2009` |
| **URL Flusso Video** | URL RTSP o WebRTC/go2rtc del flusso video | *(Opzionale)* |

> [!TIP]
> Se in futuro cambi indirizzo o attuatore, puoi cliccare su **Configura** nella scheda del dispositivo in Home Assistant per modificare i parametri senza dover reinstallare.

---

## 📹 Configurazione Flusso Video con go2rtc

L'Hometouch trasmette il flusso video tramite sessione SIP H.264. Puoi integrarlo direttamente con **go2rtc** (incluso in WebRTC Camera o Frigate):

Aggiungi nel tuo `go2rtc.yaml`:
```yaml
streams:
  videocitofono:
    - sip:<IP_HOMETOUCH>:5060
```
Nelle opzioni dell'integrazione BTicino HOMETOUCH puoi quindi inserire come **URL Flusso Video**:
```text
http://127.0.0.1:1984/api/stream.m3u8?src=videocitofono
```

---

## 🔔 Esempio di Automazione: Notifica Chiamata su Smartphone

Invia una notifica con snapshot e pulsanti per aprire portoncino e cancello direttamente dalla notifica:

```yaml
alias: "Citofono: Chiamata al campanello"
trigger:
  - platform: state
    entity_id: binary_sensor.campanello_chiamata
    to: "on"
action:
  - service: camera.snapshot
    target:
      entity_id: camera.videocitofono
    data:
      filename: /config/www/citofono_last.jpg
  - service: notify.notify
    data:
      title: "🔔 Qualcuno ha suonato al citofono!"
      message: "Chiamata in corso al posto esterno."
      data:
        image: "/local/citofono_last.jpg"
        actions:
          - action: "OPEN_PORTONCINO"
            title: "🔓 Apri Portoncino"
          - action: "OPEN_CANCELLO"
            title: "⛩️ Apri Cancello"
```

E l'automazione per gestire il tocco sui pulsanti della notifica:
```yaml
alias: "Citofono: Azione da notifica"
trigger:
  - platform: event
    event_type: mobile_app_notification_action
    event_data:
      action: "OPEN_PORTONCINO"
    id: portoncino
  - platform: event
    event_type: mobile_app_notification_action
    event_data:
      action: "OPEN_CANCELLO"
    id: cancello
action:
  - choose:
      - conditions:
          - condition: trigger
            id: portoncino
        sequence:
          - service: lock.unlock
            target:
              entity_id: lock.portoncino
      - conditions:
          - condition: trigger
            id: cancello
        sequence:
          - service: button.press
            target:
              entity_id: button.apri_cancello
```

---

## 🎛️ Esempio Card Dashboard Lovelace

```yaml
type: vertical-stack
cards:
  - type: picture-entity
    entity: camera.videocitofono
    name: Posto Esterno
    show_state: false
  - type: horizontal-stack
    cards:
      - type: button
        name: Portoncino
        icon: mdi:door-open
        tap_action:
          action: call-service
          service: lock.unlock
          target:
            entity_id: lock.portoncino
      - type: button
        name: Cancello
        icon: mdi:gate
        tap_action:
          action: call-service
          service: button.press
          target:
            entity_id: button.apri_cancello
      - type: button
        name: Luce Scale
        icon: mdi:lightbulb
        tap_action:
          action: call-service
          service: button.press
          target:
            entity_id: button.luce_scale
```
# bticino_hometouch
