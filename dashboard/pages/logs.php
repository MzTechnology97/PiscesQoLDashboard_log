<?php
$logs['miner'] = shell_exec('tail -300 /home/pi/hnt/miner/log/console.log | tac');
$logs['witnesses'] = shell_exec('tac /home/pi/hnt/miner/log/console.log | grep -E "witness|client sending data"');
$logs['validators'] = shell_exec('tac /home/pi/hnt/miner/log/console.log | grep -E "connect_validator|setup|handle_down_event"');
$logs['other'] = shell_exec('tac /home/pi/hnt/miner/log/console.log | grep -E "miner_poc_grpc_client_statem|grpc_client_stream_custom|send_grpc_unary_req|rxpk"');
$logs['errors'] = shell_exec('tail -100 /home/pi/hnt/miner/log/error.log | tac');
$logs['packet_forwarder'] = shell_exec('tail -100 /var/log/packet-forwarder/packet_forwarder.log | tac');
$connectedvalidator = shell_exec('netstat -atn | grep 8080');
$connectedvalidator = substr($connectedvalidator, -36);
$logs['beacon'] = shell_exec('tac /home/pi/hnt/miner/log/console.log | grep -E "tx_power_corrected|tx_power|TX_POWER"');
?>
<h1>Sensecap M1 Miner Dashboard - Information</h1>


<div class="log_container">
<a href="/?page=minerloganalyzer" title="Miner Log Analyzer"><span class="text"><h2>Analysis log with Helium Miner Log Analyzer</span></h2></a><br>
<a href="/?page=packetforwarder" title="Packet Forwarder Analyzer"><span class="text"><h2>Packet Forwarder Log Analyzer</span></h2></a>

<div>

<div class="log_container">
        <h2>Miner Logs</h2>
        <div class="wrapper"><textarea class="log_output" wrap="off"><?php echo $logs['miner']; ?></textarea></div>
</div>

<div class="log_container">
        <h2>Witness Logs</h2>
        <div class="wrapper"><textarea class="log_output" wrap="off"><?php echo $logs['witnesses']; ?></textarea></div>
</div>

<div class="log_container">
        <h2>Validators Logs (Connected to <?php echo $connectedvalidator; ?>)</h2>
        <div class="wrapper"><textarea class="log_output" wrap="off"><?php echo $logs['validators']; ?></textarea></div>
</div>

<div class="log_container">
        <h2>Other Logs</h2>
        <div class="wrapper"><textarea class="log_output" wrap="off"><?php echo $logs['other']; ?></textarea></div>
</div>


<div class="log_container">
        <h2>Error Logs</h2>
        <div class="wrapper"><textarea class="log_output" wrap="off"><?php echo $logs['errors']; ?></textarea></div>
</div>

<div class="log_container">
        <h2>Packet Forwarder Logs</h2>
        <div class="wrapper"><textarea class="log_output" wrap="off"><?php echo $logs['packet_forwarder']; ?></textarea></div>
</div>