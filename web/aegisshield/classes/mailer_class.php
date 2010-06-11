<?php
require("classes/phpmailer/class.phpmailer.php");

//Extend phpmailer class
class mailer extends PHPMailer{

	var $settings;
	
	//Constructor
	function mailer($settings){
		$this->settings= $settings;
	}

	//Send mail
	function send_mail($from, $from_name, $to, $to_name, $subject, $body){
		$variables=unserialize($this->settings);
		$text.=$body."\n\n----------\n".$variables['url'];
		$mail = new PHPMailer();
		$mail->From     = $from;
		$mail->FromName = $from_name;
		$mail->AddAddress($to, $to_name);
		$mail->Subject = $subject;
		$mail->Body    = $text;
		if (!$mail->Send()){
			exit('Error sending mail');
		}
	}
	
	//Send mail with file
	function send_file($from, $from_name, $to, $to_name, $subject, $body, $path_file, $file_name){
		$variables=unserialize($this->settings);
		$text.=$body."\n\n----------\n".$variables['url'];
		$mail = new PHPMailer();
		$mail->From     = $from;
		$mail->FromName = $from_name;
		$mail->AddAddress($to, $to_name);
		$mail->Subject = $subject;
		$mail->Body    = $text;
		$mail->AddAttachment($path_file, $file_name);
		if (!$mail->Send()){
			exit('Error sending mail with file');
		}
	}

}
?>