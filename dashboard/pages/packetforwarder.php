<?php
/**
 * processlogs.php
 *
 * Extracts witness data from Helium miner logs
 *
 * @author     Iñigo Flores
 * @copyright  2022 Iñigo Flores
 * @license    https://opensource.org/licenses/MIT  MIT License
 * @version    0.02
 * @link       https://github.com/inigoflores/lora-packet-forwarder-analyzer
  */

$logsPath = '/var/log/packet-forwarder/packet_forwarder.log';






$startDate = "2000-01-01";
$endDate = "2030-01-01";
$includeDataPackets = false;

// Command line options
$options = ["d","p:","s:","e:","c::","a","l","i"];
$opts = getopt(implode("",$options));

// Defaults to stats when called
if (!(isset($opts['l']) || isset($opts['c']) || isset($opts['i']))) {
    $opts['a']=true;
}

foreach ($options as $key=>$val){
    $options[$key] = str_replace(":","",$val);
}

uksort($opts, function ($a, $b) use ($options) {
    $pos_a = array_search($a, $options);
    $pos_b = array_search($b, $options);
    return $pos_a - $pos_b;
});

// Handle command line arguments
foreach (array_keys($opts) as $opt) switch ($opt) {
    case 'p':
        $logsPath = $opts['p'];
        if (substr($logsPath,strlen($logsPath)-1) != "/" && is_dir($logsPath)){
            $logsPath.="/";
        };
        break;
    case 'd':
        $includeDataPackets = true;
        break;
    case 's':
        if (!DateTime::createFromFormat('Y-m-d',  $opts['s'])){
            exit("Wrong date format");
        }
        $startDate = $opts['s'];
        break;
    case 'e':
        if (!DateTime::createFromFormat('Y-m-d',  $opts['e'])){
            exit("Wrong date format");
        }
        $endDate = $opts['e'];
        break;
    case 'c':
        $csvOutput = true;
        $filename = $opts['c'];
        break;
    case 'a':
        echo "<div class=\"log_container\">";
        echo "\nUsing logs in {$logsPath}\n\n";
        $packets = extractData($logsPath,$startDate,$endDate);
        echo generateStats($packets);
        echo generateList($packets,$includeDataPackets);
        echo "</div>";
        break;
    case 'l':
        echo "\nUsing logs in {$logsPath}\n\n";
        $includeDataPackets = true;
        $packets = extractData($logsPath,$startDate,$endDate);
        if (!$csvOutput) {
            echo generateList($packets,$includeDataPackets);
        } else {
            echo generateCSV($packets,$filename,$includeDataPackets);
        }
        exit(1);
    case 'i':
        echo "\nUsing logs in {$logsPath}\n\n";
        $packets = extractData($logsPath,$startDate,$endDate);
        $histogram = generateHistogramData($packets,$includeDataPackets);
        if (!$csvOutput) {
            echo generateHistogramASCIIChart($histogram,$includeDataPackets);
        } else {
            echo generateCSVHistogram($histogram,$filename,$includeDataPackets);
        }
        exit(1);

}


/*
 * -------------------------------------------------------------------------------------------------
 * Functions
 * -------------------------------------------------------------------------------------------------
 */

/**
 * @param $logsPath
 * @return array
 */
function extractData($logsPath, $startDate = "", $endDate = ""){

    if (is_dir($logsPath)) {
        $filenames = glob("{$logsPath}packet_forwarder*.log*");
    } else if (is_file($logsPath)) {
        $filenames = [$logsPath];
    } else {
        exit ("Path is not a valid folder or file.\n");
    }

    if (empty($filenames)){
        return '<br><br><br><h2>No logs found. Install the service and let it run for some time before running this command again</h2>';
    }

    rsort($filenames); //Order is important, from older to more recent.

    $packets = [];

    foreach ($filenames as $filename) {

        $buf = file_get_contents($filename,);
        if (substr($filename, -3) == '.gz') {
            $buf = gzdecode($buf);
        }

        $lines = explode("\n", $buf);
        unset($buf);

        foreach ($lines as $line) {

            if (!strpos($line,'xpk"')) { //empty line
                continue;
            }

            $jsonStart = strpos($line,"{");
            $jsonData = substr($line,$jsonStart);
            //$temp = explode('{"rxpk":', $line);
            $temp = explode(" ",substr($line,0,$jsonStart));
            $datetime = "{$temp[0]} $temp[1]";

            if ($datetime < $startDate || $datetime > $endDate) {
                continue;
            }

            $packet = json_decode($jsonData);


            if (empty($packet)) {
                 continue;
            }

            if (isset($packet->rxpk)) {
                $packet = $packet->rxpk[0];
                $decodedData = base64_decode($packet->data);

                if (isset($packet->rssis)) {
                    $rssi = $packet->rssis;
                } else {
                    $rssi = $packet->rssi;
                }

                if (substr($packet->data, 0, 3) == "QDD" && strlen($decodedData) == 52) {
                    $type = "witness";
                } else {
                    $type = "rx data";
                }

                $snr = $packet->lsnr;
                $freq = $packet->freq;

            } else if (isset($packet->txpk))  { //Sent beacon

                $packet = $packet->txpk;
                $decodedData = base64_decode($packet->data);

                $rssi = $packet->powe;

                if (substr($packet->data, 0, 3) == "QDD" && strlen($decodedData) == 52) {
                    $type = "beacon";
                } else {
                    $type = "tx data";
                }
                $freq = $packet->freq;
                $snr = "";
            }

            if ($type=='witness' || $type=='beacon') {
                //LongFi packet. The Onion Compact Key starts at position 12 and is 33 bytes long. THanks to @ricopt5 for helping me figure this out.
                $onionCompactKey = substr($decodedData, 12, 33);
                $hash = base64url_encode(hash('sha256', $onionCompactKey, true)); // This is the Onion Key Hash
            } else {
                $hash = base64url_encode(hash('crc32b', $decodedData, true)); //
            }
            //
            $packets[] = compact('datetime', 'freq', 'rssi', 'snr', 'type', 'hash');


        }
    }

    //Sort packets by datetime
    usort($packets, function($a, $b) {
        return $a['datetime'] <=> $b['datetime'];
    });

    return $packets;
}


/**
 * @param $packets
 * @return string
 */
function generateStats($packets) {

    if (empty($packets)) {
        return '<br><br><br><h2>"No packets found</h2>';
    }

	

    $systemDate = new DateTime();
	

    $startTime = DateTime::createFromFormat('Y-m-d H:i:s',$packets[0]['datetime'], new DateTimeZone( "Europe/Rome" ));
    $endTime = DateTime::createFromFormat('Y-m-d H:i:s',end($packets)['datetime'], new DateTimeZone( "Europe/Rome" ));
    $intervalInHours = ($endTime->getTimestamp() - $startTime->getTimestamp())/3600;
    $intervalInDays = ($endTime->getTimestamp() - $startTime->getTimestamp())/3600/24;
    $startTime->modify('+2 hours');
    $endTime->modify('+2 hours');
    //$startTime->setTimezone($systemDate->getTimezone());
   // $endTime->setTimezone($systemDate->getTimezone());

    $totalWitnesses = $totalBeacons = 0;
    $totalPackets = sizeOf($packets);
    $lowestWitnessRssi = $lowestPacketRssi = 0;

    $witnessDataByFrequency = [];
    foreach ($packets as $packet){

        if ($packet['type']=='tx data') {
            continue;

        } else if ($packet['type']=='beacon') {
            $totalBeacons++;
            continue;
        }

        $packetDataByFrequency["{$packet['freq']}"]['rssi'][] = $packet['rssi'];
        $packetDataByFrequency["{$packet['freq']}"]['snr'][] = $packet['snr'];

        if ($packet['rssi'] < $lowestPacketRssi) {
            $lowestPacketRssi = $packet['rssi'];
        }

        if ($packet['type']=='witness') {
            $totalWitnesses++;
            $witnessDataByFrequency["{$packet['freq']}"]['rssi'][] = $packet['rssi'];
            $witnessDataByFrequency["{$packet['freq']}"]['snr'][] = $packet['snr'];

            if ($packet['rssi'] < $lowestWitnessRssi) {
                $lowestWitnessRssi = $packet['rssi'];
            }
        }
    }
    foreach ($packetDataByFrequency as $freq => $rssifreq) {
        $packetRssiAverages["{$freq}"] = number_format(getMean($packetDataByFrequency["{$freq}"]['rssi']),2);
        $packetRssiMins["{$freq}"] = number_format(min($packetDataByFrequency["{$freq}"]['rssi']),2);
        $packetSnrAverages["{$freq}"] =  number_format(getMean($packetDataByFrequency["{$freq}"]['snr']),2);
    }

    foreach ($witnessDataByFrequency as $freq => $rssifreq) {
        $witnessRssiAverages["{$freq}"] = number_format(getMean($witnessDataByFrequency["{$freq}"]['rssi']) ,2);
        $witnessRssiMins["{$freq}"] = number_format(min($witnessDataByFrequency["{$freq}"]['rssi']) ,2);
        $witnessSnrsAverages["{$freq}"] =  number_format(getMean($witnessDataByFrequency["{$freq}"]['snr']),2);
    }

    $freqs = array_keys($packetDataByFrequency);
    sort($freqs);

    $totalPacketsPerHour = number_format(round($totalPackets / $intervalInHours,2),2,".","");
    $totalWitnessesPerHour = number_format(round($totalWitnesses / $intervalInHours,2), 2,".","");
    $totalBeaconsPerDay = number_format(round($totalBeacons / $intervalInDays,2), 2,".","");

    $totalPacketsPerHour = str_pad("($totalPacketsPerHour",9, " ", STR_PAD_LEFT);;
    $totalWitnessesPerHour = str_pad("($totalWitnessesPerHour",9, " ", STR_PAD_LEFT);;
    $totalBeaconsPerDay = str_pad("($totalBeaconsPerDay",9, " ", STR_PAD_LEFT);;

    $totalWitnesses = str_pad($totalWitnesses,7, " ", STR_PAD_LEFT);
    $totalBeacons = str_pad($totalBeacons,7, " ", STR_PAD_LEFT);
    $totalPackets = str_pad($totalPackets,7, " ", STR_PAD_LEFT);
    $lowestPacketRssi = str_pad($lowestPacketRssi,7," ",STR_PAD_LEFT);
    $lowestWitnessRssi = str_pad($lowestWitnessRssi,7," ",STR_PAD_LEFT);
    $intervalInHoursStr = round($intervalInHours,1);


    foreach ($freqs as $freq) {
        $numberOfWitnesses = @str_pad(count($witnessDataByFrequency[$freq]['rssi']), 4, " ", STR_PAD_LEFT);
        $witnessRssi = @str_pad($witnessRssiAverages["{$freq}"] , 7, " ", STR_PAD_LEFT);
        $witnessSnr = @str_pad($witnessSnrsAverages["{$freq}"] , 6, " ", STR_PAD_LEFT);
        $witnessRssiMin = @str_pad($witnessRssiMins["{$freq}"] , 7, " ", STR_PAD_LEFT);

        $numberOfPackets = str_pad(count($packetDataByFrequency[$freq]['rssi']), 6, " ", STR_PAD_LEFT);
        $packetRssi = str_pad($packetRssiAverages["{$freq}"] , 7, " ", STR_PAD_LEFT);
        $packetSnr = str_pad($packetSnrAverages["{$freq}"] , 6, " ", STR_PAD_LEFT);
        $packetRssiMin = str_pad($packetRssiMins["{$freq}"] , 7, " ", STR_PAD_LEFT);

        //$output.= "$freq | $numberOfWitnesses |  $witnessRssi |  $witnessRssiMin | $witnessSnr | $numberOfPackets |  $packetRssi |  $packetRssiMin | $packetSnr " . PHP_EOL;
		
    };
   
    $output = '<br><br><p><br><h2 style="color:#F0FF00;">General Witnesses Overview</h2></p><br>';
	$output.='<table border="1" style="width: 100%; height: 100%">';
	$output.= "
		<tr border='1' align='left' style='color:#F0FF00' >
		<th style='width:60%'> Description </th>
		<th align='center'> Value </th>
		<th align='center'> Precentage </th>
		</tr>";
    $output.= "
		<tr border='1'>
			<td> First Packet </td>
			  <td align='center'> {$startTime->format("d-m-Y H:i:s")} </td>
		</tr>";
    $output.= "
		<tr border='1'>
			<td> Last Packet </td>
			  <td align='center'> {$endTime->format("d-m-Y H:i:s")} </td>
		</tr>";
	$output.= "
		<tr border='1'>
			<td> Total Witnesses </td>
			  <td align='center'> {$totalWitnesses} </td>
			 <td align='center'> {$totalWitnessesPerHour} / hour  </td>
		</tr>";
    $output.= "
		<tr border='1'>
			<td> Total Packets </td>
			  <td align='center'> {$totalPackets} </td>
			 <td align='center'> {$totalPacketsPerHour} / hour  </td>
		</tr>";
    $output.= "
		<tr border='1'>
			<td> Total Beacon </td>
			  <td align='center'> {$totalBeacons} </td>
			 <td align='center'> {$totalBeaconsPerDay} / day  </td>
		</tr>";
    $output.= "
		<tr border='1'>
			<td> Lowest Witness RSSI </td>
			  <td align='center'> {$lowestWitnessRssi} / dBm\n </td>
		</tr>";
        
    $output.= "
		<tr border='1'>
			<td> Lowest Packet RSSI </td>
			  <td align='center'> {$lowestPacketRssi} / dBm\n </td>
		</tr>";


		
	$output.= " </table>";

    return $output;
}


/**
 * @param $packets
 * @param $includeDataPackets
 * @return string
 */
function generateList($packets, $includeDataPackets = true) {

    if (empty($packets)) {
		return;
	}

	$output = '<br><p><br><h2 style="color:#F0FF00;">All signal List</h2></p>';
	$output .= '<br>
		<table border="1" style="width: 100%; height: 100%">
		<tr style="color:#FCF3CF ;">
		<th align="left">Date</th>
		<th align="left">Type</th>
		<th align="left">Freq</th>
		<th align="left">RSSI</th>
        <th align="left">SNR</th>
		<th align="left">Noise</th>
        <th align="left">Hash</th>
		</tr>';

		
        
    $systemDate = new DateTime();
    $utc = new DateTimeZone( "Europe/Rome" );
    foreach (array_reverse($packets) as $packet){

        if (($packet['type']=="tx data" || $packet['type']=="rx data") && $includeDataPackets){
            continue;
        }

        $datetime = DateTime::createFromFormat('Y-m-d H:i:s',$packet['datetime'], $utc);
        //$datetime->setTimezone($systemDate->getTimezone());
        $datetime->modify('+2 hours');

        $rssi = str_pad($packet['rssi'], 4, " ", STR_PAD_LEFT);

        if ($packet['type']=="witness"||$packet['type']=="rx data"){
            $noise = number_format((float)($packet['rssi'] - $packet['snr']));
        } else {
            $noise = "";
        }

        $snrStr = str_pad($packet['snr'], 5, " ", STR_PAD_LEFT);
        $noiseStr = str_pad($noise,  6, " ", STR_PAD_LEFT);
        $type = str_pad($packet['type'],7,  " ", STR_PAD_LEFT);
        $hash = @str_pad($packet['hash'],44, " ", STR_PAD_RIGHT);
	    $datetimeStr = $datetime->format("M-d H:i:s");
        //$output.=@"$datetimeStr | {$packet['freq']} | {$rssi} | {$snrStr} | {$noiseStr} | $type {$hash}<br>";
       //$output.=@"{$datetimeStrdt->format('M-d H:i:s')} | {$rssi} | {$packet['freq']} | {$snrStr} | {$noiseStr}  {$hash} <br>";
        
        $output.=@"
		<tr border='1' align='left' style='color:#17D9E3'>
			<td style='width: auto'> {$datetimeStr} </td>
			<td> {$type} </td>
			<td> {$packet['freq']} </td>
            <td> {$rssi} </td>
			<td> {$snrStr} </td>
			<td> {$noiseStr} </td>
            <td><div style='overflow-x:auto; overflow-y: hidden; white-space: nowrap; width:100px; height: auto;' > {$hash} </div></td>
            </tr>";
    }
     return $output."</table>";

}

/**
 * @param $packets
 * @param $includeDataPackets
 * @return string
 */



/**
 * @param $packets
 * @param $includeDataPackets
 * @return string
 */


/**
 * @param $packets
 * @param $includeDataPackets
 * @return string
 */


/**
 * @param $packets
 * @param $includeDataPackets
 * @return string
 */


/**
 * @param $fields
 * @param string $delimiter
 * @param string $enclosure
 * @param string $escape_char
 * @return false|string
 */


function getMedian($arr) {
    sort($arr);
    $count = count($arr);
    $middleval = floor(($count-1)/2);
    if ($count % 2) {
        $median = $arr[$middleval];
    } else {
        $low = $arr[$middleval];
        $high = $arr[$middleval+1];
        $median = (($low+$high)/2);
    }
    return $median;
}

function getMean($arr) {
    $count = count($arr);
    return array_sum($arr)/$count;
}

function base64url_encode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}