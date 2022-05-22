<?php
if($_GET['submit'])
{
	if($_POST['type'] == 'PPTP')
	{
		$details = $_POST['username']."\n".$_POST['password']."\n".$_POST['serveraddress']."\n".$_POST['serverport']."\n".$_POST['serverporttype'];
		$file = fopen('/var/dashboard/vpn/pptp_details', 'w');
		fwrite($file, $details);
		fclose($file);
		$template = file_get_contents('/var/dashboard/vpn/pptp_template');
		$details = explode("\n", file_get_contents('/var/dashboard/vpn/pptp_details'));

		$final = str_replace(":username", $details[0], $template);
		$final = str_replace(":password", $details[1], $final);
		$final = str_replace(":hostname", $details[2], $final);
		$final = str_replace(":serverport", $details[4], $final);

		$file = fopen('/var/dashboard/vpn/pptp_config', 'w');
		fwrite($file, $final);
		fclose($file);

		$file = fopen('/var/dashboard/services/vpn', 'w');
		fwrite($file, 'newconfig:pptp');
		fclose($file);
	}
	else
	{
		$details = $_POST['username']."\n".$_POST['password']."\n".$_POST['serveraddress']."\n".$_POST['serverport']."\n".$_POST['serverporttype'];
		$file = fopen('/var/dashboard/vpn/ovpn_details', 'w');
		fwrite($file, $details);
		fclose($file);
		$template = file_get_contents('/var/dashboard/vpn/ovpn_template');
		$details = explode("\n", file_get_contents('/var/dashboard/vpn/ovpn_details'));

		$auth = $details[0]."\n".$details[1];
		$file = fopen('/var/dashboard/vpn/auth.txt', 'w');
		fwrite($file, $auth);
		fclose($file);

		$final = str_replace(':hostname', $details[2], $template);
		$final = str_replace(':port', $details[4], $final);

		if($_POST['serverporttype'] == 'UDP')
		{
			$final = str_replace(':type', 'udp4', $final);
		}
		else
		{
			$final = str_replace(':type', 'tcp4', $final);
		}

		$file = fopen('/var/dashboard/vpn/ovpn_config', 'w');
		fwrite($file, $final);
		fclose($file);

		$file = fopen('/var/dashboard/services/vpn', 'w');
		fwrite($file, 'newconfig:openvpn');
		fclose($file);

	}

	header('Location: ?page=configurevpn');

}


$service = explode(":", file_get_contents('/var/dashboard/services/vpn'));
$vpn_type = trim($service[1]);

if($vpn_type == 'openvpn')
{
	$server_details = explode("\n", file_get_contents('/var/dashboard/vpn/ovpn_details'));
	$info['Username'] = trim($server_details[0]);
	$info['Password'] = trim($server_details[1]);
	$info['Server'] = trim($server_details[2]);
	$info['ServerPort'] = trim($server_details[3]);
	$info['ServerPortType'] = trim($server_details[4]);
}
else if($vpn_type == 'pptp')
{
	$server_details = explode("\n", file_get_contents('/var/dashboard/vpn/pptp_details'));
	$info['Username'] = trim($server_details[0]);
	$info['Password'] = trim($server_details[1]);
	$info['Server'] = trim($server_details[2]);
	$info['ServerPort'] = trim($server_details[3]);
	$info['ServerPortType'] = trim($server_details[4]);
}
?>

<h1>Pisces P100 Outdoor Miner Dashboard - Configure VPN</h1>

<form id="vpn_info" action="?page=configurevpn&submit=1" method="post">
	<ul>
		<li>
			<label for="type">Type:</label>
			<select name="type">
				<option value="OpenVPN" <?php if($vpn_type == 'openvpn') { echo ' selected'; } ?>>OpenVPN</option>
				<option value="PPTP" <?php if($vpn_type == 'pptp') { echo ' selected'; } ?>>PPTP</option>
			</select>
		</li>

		<li>
			<label for="serveraddress">Server Name/Address:</label>
			<input type="text" name="serveraddress" value="<?php echo $info['Server']; ?>" />
		</li>

		<li>
			<label for="serverport">Server Port:</label>
			<input type="text" name="serverport" value="<?php echo $info['ServerPort']; ?>" />
		</li>

		<li>
			<label for="serverporttype">Connection Type:</label>
			<select name="serverporttype">
				<option value="UDP" <?php if($info['ServerPortType'] == 'UDP') { echo ' selected'; } ?>>UDP</option>
				<option value="TCP" <?php if($info['ServerPortType'] == 'TCP') { echo ' selected'; } ?>>TCP</option>
			</select>
		</li>

		<li>
			<label for="username">Username:</label>
			<input type="text" name="username" value="<?php echo $info['Username']; ?>" />
		</li>

		<li>
			<label for="password">Password:</label>
			<input type="password" name="password" value="<?php echo $info['Password']; ?>" />
		</li>

		<li>
			<input type="submit" value="Submit" />
		</li>
	</ul>
</form>
