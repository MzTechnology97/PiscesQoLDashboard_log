<?php
/**
 * minerloganalyzer.php
 *
 * Extracts witness data from Helium miner logs
 *
 * @author     I�igo Flores
 * @copyright  2022 I�igo Flores
 *             2022 Fengling
 * @license    https://opensource.org/licenses/MIT  MIT License
 * @version    0.01
 * @link       https://github.com/inigoflores/helium-miner-log-analyzer
 */

$logsFolder = '/home/pi/hnt/miner/log/';

$startDate = "2000-01-01";
$endDate = "2030-01-01";

// Command line options
$options = ["p:","s:","e:","a","l","c::"];
$opts = getopt(implode("",$options));

// Defaults to stats when called
if (!(isset($opts['l']) || isset($opts['c']))) {
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
	$logsFolder = $opts['p'];
	if (substr($logsFolder,strlen($logsFolder)-1) != "/"){
		$logsFolder.="/";
	};
	break;
case 's':
	if (!DateTime::createFromFormat('Y-m-d',  $opts['s'])){
		echo "Wrong date format";
		break;
	}
	$startDate = $opts['s'];
	break;
case 'e':
	if (!DateTime::createFromFormat('Y-m-d',  $opts['e'])){
		echo "Wrong date format";
		break;
	}
	$endDate = $opts['e'];
	break;
case 'a':
	echo "<div class=\"log_container\">";
	echo "\nUsing logs in folder {$logsFolder}\n\n";
	$beacons = extractData($logsFolder,$startDate,$endDate);
	echo generateStats($beacons);
	echo generateList($beacons);
	echo "</div>";
	break;

case 'l':
	echo "<div class=\"log_container\">";
	echo "\nUsing logs in folder {$logsFolder}\n\n";
	$beacons = extractData($logsFolder,$startDate,$endDate);
	echo generateList($beacons);
	echo "</div>";
	break;

case 'c':
	echo "<div class=\"log_container\">";
	$beacons = extractData($logsFolder,$startDate,$endDate);
	$filename = $opts['c'];
	echo generateCSV($beacons,$filename);
	echo "</div>";
	break;
}

/*
 * -------------------------------------------------------------------------------------------------
 * Functions
 * -------------------------------------------------------------------------------------------------
 */

/**
 * @param $beacons
 * @return string
 */
function generateStats($beacons) {


	if (empty($beacons)) {
		return '<br><br><br><h2>No witnesses found</h2>';
	}

	$startTime = DateTime::createFromFormat('Y-m-d H:i:s',explode('.',$beacons[0]['datetime'])[0]);
	$endTime = DateTime::createFromFormat('Y-m-d H:i:s',explode('.',end($beacons)['datetime'])[0]);
	$intervalInHours = ($endTime->getTimestamp() - $startTime->getTimestamp())/3600;

	$successful = 0;

	foreach ($beacons as $beacon){

		// General Witnesses Overview
		if ($beacon['status']=='successfully sent') {
			$successful++;
		}

		
	}

	$total = sizeOf($beacons);
	$totalFailed = $total - $successful;
	$totalPerHour = round($total / $intervalInHours,2);

	$totalFailedOther = $failedNoListenAddress +  $failedConRefused + $failedHostUnreach;

	$percentageSuccessful = round($successful/$total*100,2);
	$percentageFailed = round($totalFailed/$total*100,2);

	$percentageRelayUnknown = round(($total-$notRelayed-$relayed)/$total*100,2);
	$Unknown = $total - $notRelayed - $relayed;

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
			<td> Total witnesses </td>
			  <td align='center'> {$total} </td>
			 <td align='center'> {$totalPerHour} / hour  </td>
		</tr>";
	$output.= "
		<tr border='1' style='color: #30ff00 ' >
			<td> Succesfully delivered  </td>
			<td align='center'> {$successful} </td>
			 <td align='center'> {$percentageSuccessful} %</td>
		</tr> ";
	$output.= "
		<tr border='1'style='color:	#FF0000 ' >
			<td> Failed  </td>
			 <td align='center'> {$totalFailed} </td>
			 <td align='center'> {$percentageFailed}% </td>
		</tr> ";

	$output.= " </table>";


	return $output;
}

/**
 * @param $beacons
 * @return string
 */
function generateList($beacons) {

	if (empty($beacons)) {
		return;
	}
	$output = '<br><p><br><h2 style="color:#F0FF00;">Witnesses List</h2></p>';
	$output .= '<br>
		<table border="1" style="width: 100%; height: 100%">
		<tr style="color:#FCF3CF ;">
		<th align="left">Date</th>
		<th>RSSI</th>
		<th>Freq</th>
		<th>SNR</th>
		<th>Noise</th>
		<th>Status</th>
		</tr>';

	foreach (array_reverse($beacons) as $beacon){

		$rssi = str_pad($beacon['rssi'], 4, " ", STR_PAD_LEFT);
		$snr = str_pad($beacon['snr'], 5, " ", STR_PAD_LEFT);
		$noise = str_pad(number_format((float) ($beacon['rssi'] - $beacon['snr']),1),6,  " ", STR_PAD_LEFT);
		$status = str_pad($beacon['status'], 17, " ", STR_PAD_RIGHT);
		$failures = str_pad(empty($beacon['failures'])?0:$beacon['failures'], 5, " ", STR_PAD_LEFT);
		$reasonShort = @$beacon['reasonShort'];
		$session = str_pad($beacon['session'],11, " ", STR_PAD_LEFT);;

		$dt = DateTime::createFromFormat('Y-m-d H:i:s.u',$beacon['datetime']);
        $dt->setTimezone(new DateTimeZone( "Europe/Rome" )); 
		
		#$dt->modify('+4 hours');

		$output.=@"
		<tr border='1'>
			<td> {$dt->format("d-m-Y H:i:s")} </td>
			<td> {$rssi} </td>
			<td> {$beacon['freq']} </td>
			<td> {$snr} </td>
			<td> {$noise} </td>
			<td> {$status} </td>
		</tr>";
	}

	return $output."</table>";
}
function generateList2($beacons) {
	$output = "<br><br>Date                    | RSSI | Freq  | SNR   | Noise    | Status                                         | Relay | Status            | Fails | Reason <br>";
	$output.= "------------------------------------------------------------------------------------ <br>";

	foreach ($beacons as $beacon){

		$rssi = str_pad($beacon['rssi'], 4, " ", STR_PAD_LEFT);
		$snr = str_pad($beacon['snr'], 5, " ", STR_PAD_LEFT);
		$noise = str_pad(number_format((float) ($beacon['rssi'] - $beacon['snr']),1),6,  " ", STR_PAD_LEFT);
		$status = str_pad($beacon['status'], 17, " ", STR_PAD_RIGHT);
		$reasonShort = @$beacon['reasonShort'];
	//	$reason = @$beacon['reason'];


		$dt = new DateTime($beacon['datetime']);
		//$dt->modify('+4 hours');

		$output.=@"{$dt->format('M-d H:i:s')} | {$rssi} | {$beacon['freq']} | {$snr} | {$noise}  {$status} <br>";

	}
	return $output;
}

/**
 * @param $logsFolder
 * @return array
 */
function extractData($logsFolder, $startDate, $endDate){

	$beacons = [];
	$filenames = glob("{$logsFolder}console*.log*");

	if (empty($filenames)){
		echo "No logs found. Please chdir to the Helium miner logs folder or specify a path.\n";
		return $beacons;
	}

	rsort($filenames); //Order is important, from older to more recent.

	foreach ($filenames as $filename) {

		$buf = file_get_contents($filename,);
		if(substr($filename, -3) == '.gz') {
			$buf = gzdecode($buf);
		}

		$lines = explode("\n", $buf);
		unset($buf);

		foreach ($lines as $line) {

			if (preg_match('/miner_onion_server_light:decrypt:{[0-9]+,[0-9]+} (?:re-)?sending witness at RSSI/', $line) ||
			   (preg_match('/@miner_poc_grpc_client_statem:send_report:{[0-9]+,[0-9]+} failed to submit report/', $line)))
			{
                $fields = explode(' ', $line);
                $datetime = $fields[0] . " " . $fields[1];
                if ($datetime<$startDate || $datetime>$endDate) {
                    continue;
                }
                $session = explode('>',explode('<', $fields[4])[1])[0];
            } else {
                continue;
            }

            if (preg_match('/sending witness at RSSI/', $line)){
                $rssi = substr($fields[9], 0, -1);
                $freq = substr($fields[11], 0, -1);
                $snr = $fields[13];
                $status = "successfully sent";
                $beacons[$rssi.$freq.$snr] = array_merge((array)@$beacons[$rssi.$freq.$snr], compact('datetime', 'rssi', 'freq', 'snr', 'status'));
                continue;
            }

            if (preg_match('/failed to submit report/', $line)){
                $temp = explode('<<',$fields[13]);
                $temp1 = explode("," , $temp[1]);
                $temp3 = explode("," , $temp[3]);

                $rssi = $temp1[sizeof($temp1)-2];
                $freq = $temp3[2];
                $snr = $temp3[1];
                $status = "failed";
                $beacons[$rssi.$freq.$snr] = array_merge((array)@$beacons[$rssi.$freq.$snr], compact('datetime', 'rssi', 'freq', 'snr', 'status'));
                continue;
            }

		}
	}
	//
	foreach ($beacons as $session => $beacon) {
		if (empty(@$beacon['rssi'])) {
			unset($beacons[$session]);
		}
	}

	usort($beacons, function($a, $b) {
		return $a['datetime'] <=> $b['datetime'];
	});

	return $beacons;
}


/**
 * @param $beacons
 * @return string
 */
function generateCSV($beacons, $filename=false) {
	$columns = ['Date','Session','RSSI','Freq','SNR','Noise','Relay','Status','Fails','Reason'];
	$data = array2csv($columns);
	foreach ($beacons as $beacon){
		$noise = number_format((float) ($beacon['rssi'] - $beacon['snr']),1);
		$failures = empty($beacon['failures'])?0:$beacon['failures'];
		$data.= @array2csv([
			$beacon['datetime'],$beacon['session'],$beacon['rssi'],
			$beacon['freq'],$beacon['snr'],$noise,
			$beacon['relayed'],$beacon['status'],$failures,$beacon['reasonShort']]);

	}

	if ($filename) {
		$data = "SEP=;" . $data;
		file_put_contents($filename,$data);
		return "Data saved to $filename\n";
	}

	return $data;

}

/**
 * @param $fields
 * @param string $delimiter
 * @param string $enclosure
 * @param string $escape_char
 * @return false|string
 */
function array2csv($fields, $delimiter = ",", $enclosure = '"', $escape_char = '\\')
{
	$buffer = fopen('php://temp', 'r+');
	fputcsv($buffer, $fields, $delimiter, $enclosure, $escape_char);
	rewind($buffer);
	$csv = fgets($buffer);
	fclose($buffer);
	return $csv;
}

