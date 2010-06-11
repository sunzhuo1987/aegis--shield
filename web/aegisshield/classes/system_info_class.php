<?php
//System_info class
class system_info{

	//Constructor
	function system_info(){}
	
	//Get kernel version
	function GetKernelVersion(){
		if ($fd = fopen('/proc/version', 'r')){
			$buf = fgets($fd, 4096);
			fclose($fd);
		
			if (preg_match('/version (.*?) /', $buf, $ar_buf)){
			$buffer = $ar_buf[1];
				if (preg_match('/SMP/', $buf)){
				$buffer .= ' (SMP)';
				}
			}
			else{
				$buffer = 'N.A.';
			} 
		}
		else{
			$buffer = 'N.A.';
		} 
		return $buffer;
	}
	
	//Get server uptime
	function GetUptime(){
		$fd = fopen('/proc/uptime', 'r');
		$ar_buf = split(' ', fgets($fd, 4096));
		fclose($fd);
	
		$sys_ticks = trim($ar_buf[0]);
	
		$min = $sys_ticks / 60;
		$hours = $min / 60;
		$days = floor($hours / 24);
		$hours = floor($hours - ($days * 24));
		$min = floor($min - ($days * 60 * 24) - ($hours * 60));
	
		if ($days != 0) {
			$buffer = "$days days ";
		} 
	
		if ($hours != 0) {
			$buffer .= "$hours hours ";
		} 
		$buffer .= "$min minutes";
		
		return $buffer;
	}

	//Get distro information
	function getDistroInfo(){
		if ($fd = @fopen('/etc/debian_version', 'r')){
			$buf = fgets($fd, 1024);
		fclose($fd);
		$buffer = 'Debian ' . trim($buf);
		}
		elseif ($fd = @fopen('/etc/SuSE-release', 'r')){
			$buf = fgets($fd, 1024);
			fclose($fd);
			$buffer = trim($buf);
		}
		elseif($fd = @fopen('/etc/mandrake-release', 'r')){
			$buf = fgets($fd, 1024);
			fclose($fd);
			$buffer = trim($buf);
		}
		elseif ($fd = @fopen('/etc/fedora-release', 'r')){
			$buf = fgets($fd, 1024);
			fclose($fd);
			$buffer = trim($buf);
		}
		elseif ($fd = @fopen('/etc/redhat-release', 'r')){
			$buf = fgets($fd, 1024);
			fclose($fd);
			$buffer = trim($buf);
		}
		elseif ($fd = @fopen('/etc/gentoo-release', 'r')){
			$buf = fgets($fd, 1024);
			fclose($fd);
			$buffer = trim($buf);
		}
		elseif ($fd = @fopen('/etc/slackware-version', 'r')){
			$buf = fgets($fd, 1024);
			fclose($fd);
			$buffer = trim($buf);
		}
		elseif ($fd = @fopen('/etc/eos-version', 'r')){
			$buf = fgets($fd, 1024);
			fclose($fd);
			$buffer = trim($buf);
		}
		elseif ($fd = @fopen('/etc/trustix-release', 'r')){
			$buf = fgets($fd, 1024);
			fclose($fd);
			$buffer = trim($buf);
		}
		elseif ($fd = @fopen('/etc/arch-release', 'r')){
			$buf = fgets($fd, 1024);
			fclose($fd);
			$buffer = trim($buf);
		}
		else{
			$buffer = 'N.A.';
		}
		return $buffer;
	}

}
?>