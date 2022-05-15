<?php

$action = strip_tags(htmlentities($_GET['action']));

switch($action)
{
	case 'PF':
		$file = fopen('/var/dashboard/services/PF', 'w');
		fwrite($file, "stop\n");
		fclose($file);
	break;

	case 'BT':
		$file = fopen('/var/dashboard/services/BT', 'w');
		fwrite($file, "stop\n");
		fclose($file);
	break;

	case 'miner':
		$file = fopen('/var/dashboard/services/miner', 'w');
		fwrite($file, "stop\n");
		fclose($file);
	break;

	case 'GPS':
		$file = fopen('/var/dashboard/services/GPS', 'w');
		fwrite($file, "stop\n");
		fclose($file);
	break;

	case 'WiFi':
		$file = fopen('/var/dashboard/services/wifi', 'w');
		fwrite($file, "stop\n");
		fclose($file);
	break;

	case 'AutoMaintain':
		$file = fopen('/var/dashboard/services/auto-maintain', 'w');
		fwrite($file, "disabled\n");
		fclose($file);
	break;

	case 'AutoUpdate':
		$file = fopen('/var/dashboard/services/auto-update', 'w');
		fwrite($file, "disabled\n");
		fclose($file);
	break;

	case 'VPN':
		$current = file_get_contents('/var/dashboard/services/vpn');
		$newstate = str_replace('enabled', 'stop', $current);
		$file = fopen('/var/dashboard/services/vpn', 'w');
		fwrite($file, $newstate);
		fclose($file);
	break;
}
?>
