<?php

declare(strict_types=1);

class DeviceMonitor extends IPSModule
{
    public function Create()
    {
        //Never delete this line!
        parent::Create();

        // ORIGINAL Properties
        $this->RegisterPropertyBoolean('Active', false);
        $this->RegisterPropertyString('IPAddress', '');
        $this->RegisterPropertyInteger('PingTimeout', 1000);
        $this->RegisterPropertyInteger('UpdateInterval', 60);
        $this->RegisterPropertyBoolean('UseRetries', false);
        $this->RegisterPropertyInteger('Retries', 3);
        $this->RegisterPropertyString('MACAddress', '');
        $this->RegisterPropertyString('BroadcastAddress', '');

        // NEU: DNS Properties
        $this->RegisterPropertyBoolean('UseDNS', false);
        $this->RegisterPropertyString('DNSName', '');

        // ORIGINAL Variablen Profile erstellen
        if (!IPS_VariableProfileExists('DM.Status')) {
            IPS_CreateVariableProfile('DM.Status', 0); // Boolean
            IPS_SetVariableProfileIcon('DM.Status', 'Network');
            IPS_SetVariableProfileAssociation('DM.Status', false, 'Offline', '', 0xFF0000);
            IPS_SetVariableProfileAssociation('DM.Status', true, 'Online', '', 0x00FF00);
        }

        if (!IPS_VariableProfileExists('DM.WOL')) {
            IPS_CreateVariableProfile('DM.WOL', 1); // Integer
            IPS_SetVariableProfileIcon('DM.WOL', 'Power');
            IPS_SetVariableProfileAssociation('DM.WOL', 0, 'Wake On Lan', '', -1);
        }

        // ORIGINAL Variablen
        $this->RegisterVariableBoolean('DeviceStatus', 'Status', 'DM.Status', 0);
        $this->RegisterVariableInteger('LastOffline', $this->Translate('Zuletzt offline'), '~UnixTimestamp', 1);
        $this->RegisterVariableString('LastSeen', $this->Translate('Last Seen'), '', 2);
        $this->RegisterVariableString('ResolvedIP', $this->Translate('Resolved IP'), '', 3);
        $this->RegisterVariableInteger('DeviceWOL', $this->Translate('Wake On Lan'), 'DM.WOL', 4);
        $this->EnableAction('DeviceWOL');

        // Timer
        $this->RegisterTimer('UpdateTimer', 0, 'DM_UpdateStatus($_IPS[\'TARGET\']);');
    }

    public function ApplyChanges()
    {
        //Never delete this line!
        parent::ApplyChanges();

        if ($this->ReadPropertyBoolean('Active')) {
            $this->SetTimerInterval('UpdateTimer', $this->ReadPropertyInteger('UpdateInterval') * 1000);
            $this->UpdateStatus();
        } else {
            $this->SetTimerInterval('UpdateTimer', 0);
        }
    }

    public function UpdateStatus()
    {
        if (!$this->ReadPropertyBoolean('Active')) {
            return;
        }

        $useDNS = $this->ReadPropertyBoolean('UseDNS');
        $host = '';

        if ($useDNS) {
            $dnsName = $this->ReadPropertyString('DNSName');
            if (empty($dnsName)) {
                $this->SendDebug('DeviceMonitor', 'DNS-Name ist leer', 0);
                return;
            }
            // DNS zu IP auflösen
            $host = gethostbyname($dnsName);
            if ($host === $dnsName) {
                // DNS-Auflösung fehlgeschlagen
                $this->SendDebug('DeviceMonitor', "DNS-Auflösung für '$dnsName' fehlgeschlagen", 0);
                SetValue($this->GetIDForIdent('DeviceStatus'), false);
                SetValue($this->GetIDForIdent('ResolvedIP'), 'DNS-Auflösung fehlgeschlagen');
                SetValue($this->GetIDForIdent('LastOffline'), time());
                return;
            }
            $this->SendDebug('DeviceMonitor', "DNS '$dnsName' aufgelöst zu IP: $host", 0);
        } else {
            // Original: IP-Adresse verwenden
            $host = $this->ReadPropertyString('IPAddress');
            if (empty($host)) {
                $this->SendDebug('DeviceMonitor', 'IP-Adresse ist leer', 0);
                return;
            }
        }

        // ORIGINAL: Ping durchführen
        $timeout = $this->ReadPropertyInteger('PingTimeout');
        $useRetries = $this->ReadPropertyBoolean('UseRetries');
        $retries = $this->ReadPropertyInteger('Retries');

        $isOnline = false;
        $attempts = $useRetries ? $retries : 1;

        for ($i = 0; $i < $attempts; $i++) {
            if ($this->Ping($host, $timeout)) {
                $isOnline = true;
                break;
            }
            if ($i < $attempts - 1) {
                usleep(500000);
            }
        }

        SetValue($this->GetIDForIdent('DeviceStatus'), $isOnline);

        if ($isOnline) {
            SetValue($this->GetIDForIdent('LastSeen'), date('d.m.Y H:i:s'));
        } else {
            SetValue($this->GetIDForIdent('LastOffline'), time());
        }

        // Speichere die aufgelöste/verwendete IP
        SetValue($this->GetIDForIdent('ResolvedIP'), $host);

        $this->SendDebug('DeviceMonitor', "Host '$host' ist " . ($isOnline ? 'ONLINE' : 'OFFLINE'), 0);
    }

    private function Ping(string $host, int $timeout): bool
    {
        if (empty($host)) {
            return false;
        }

        $timeoutSec = max(1, intval($timeout / 1000));

        if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
            $cmd = "ping -n 1 -w $timeout $host";
        } else {
            $cmd = "ping -c 1 -W $timeoutSec $host";
        }

        exec($cmd, $output, $returnCode);

        return ($returnCode === 0);
    }

    public function WakeOnLan()
    {
        $mac = $this->ReadPropertyString('MACAddress');
        $broadcast = $this->ReadPropertyString('BroadcastAddress');

        if (empty($mac)) {
            $this->SendDebug('DeviceMonitor', 'MAC-Adresse fehlt', 0);
            return false;
        }

        if (empty($broadcast)) {
            $broadcast = '255.255.255.255';
        }

        // MAC-Adresse bereinigen
        $mac = str_replace([':', '-', ' '], '', $mac);

        if (strlen($mac) != 12) {
            $this->SendDebug('DeviceMonitor', 'Ungültige MAC-Adresse', 0);
            return false;
        }

        // Magic Packet erstellen
        $macBinary = '';
        for ($i = 0; $i < 12; $i += 2) {
            $macBinary .= chr(hexdec(substr($mac, $i, 2)));
        }

        $packet = str_repeat(chr(255), 6) . str_repeat($macBinary, 16);

        // Socket erstellen und senden
        $socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
        if ($socket === false) {
            $this->SendDebug('DeviceMonitor', 'Socket konnte nicht erstellt werden', 0);
            return false;
        }

        socket_set_option($socket, SOL_SOCKET, SO_BROADCAST, 1);
        $result = socket_sendto($socket, $packet, strlen($packet), 0, $broadcast, 9);
        socket_close($socket);

        if ($result === false) {
            $this->SendDebug('DeviceMonitor', 'Magic Packet konnte nicht gesendet werden', 0);
            return false;
        }

        $this->SendDebug('DeviceMonitor', "Magic Packet an $mac gesendet (Broadcast: $broadcast)", 0);
        return true;
    }

    public function RequestAction($Ident, $Value)
    {
        switch ($Ident) {
            case 'DeviceWOL':
                $this->WakeOnLan();
                SetValue($this->GetIDForIdent('DeviceWOL'), 0);
                break;
            default:
                throw new Exception('Invalid Ident');
        }
    }

    public function GetConfigurationForm()
    {
        $form = [
            'elements' => [
                [
                    'type' => 'CheckBox',
                    'name' => 'Active',
                    'caption' => 'Aktiv'
                ],
                [
                    'type' => 'Label',
                    'label' => '═══ Gerät ═══'
                ],
                [
                    'type' => 'CheckBox',
                    'name' => 'UseDNS',
                    'caption' => 'DNS-Name verwenden (statt IP-Adresse)'
                ],
                [
                    'type' => 'ValidationTextBox',
                    'name' => 'DNSName',
                    'caption' => 'DNS-Name'
                ],
                [
                    'type' => 'ValidationTextBox',
                    'name' => 'IPAddress',
                    'caption' => 'IP-Adresse'
                ],
                [
                    'type' => 'Label',
                    'label' => '═══ Ping-Einstellungen ═══'
                ],
                [
                    'type' => 'NumberSpinner',
                    'name' => 'PingTimeout',
                    'caption' => 'Ping Timeout',
                    'suffix' => 'ms',
                    'minimum' => 100,
                    'maximum' => 10000
                ],
                [
                    'type' => 'NumberSpinner',
                    'name' => 'UpdateInterval',
                    'caption' => 'Update Intervall',
                    'suffix' => 's',
                    'minimum' => 5,
                    'maximum' => 3600
                ],
                [
                    'type' => 'CheckBox',
                    'name' => 'UseRetries',
                    'caption' => 'Fehlversuche aktiv'
                ],
                [
                    'type' => 'NumberSpinner',
                    'name' => 'Retries',
                    'caption' => 'Versuche',
                    'minimum' => 1,
                    'maximum' => 10
                ],
                [
                    'type' => 'Label',
                    'label' => '═══ Wake on LAN ═══'
                ],
                [
                    'type' => 'ValidationTextBox',
                    'name' => 'MACAddress',
                    'caption' => 'MAC-Adresse'
                ],
                [
                    'type' => 'ValidationTextBox',
                    'name' => 'BroadcastAddress',
                    'caption' => 'Broadcast Adresse'
                ]
            ],
            'actions' => [
                [
                    'type' => 'Button',
                    'label' => 'Status aktualisieren',
                    'onClick' => 'DM_UpdateStatus($id);'
                ],
                [
                    'type' => 'Button',
                    'label' => 'Wake on LAN',
                    'onClick' => 'DM_WakeOnLan($id);'
                ]
            ]
        ];

        return json_encode($form);
    }
}