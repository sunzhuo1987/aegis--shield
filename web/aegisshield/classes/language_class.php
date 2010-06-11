<?php
//Utility class
class language{

	//Constructor
	function language(){}
	
	//Get language array
	function getLanguages(){
		$languages=array();
		if ($handle = @opendir('lang')) {
			while (false !== ($file = readdir($handle))) { 
				if ($file!='.' && $file!='..' && is_dir('lang/'.$file)){
					$languages[]=$file;
				}
			}
			closedir($handle); 
		}
		return $languages;
	}
	
	//Get language list
	function languagesList($lang=false){
		$languages=$this->getLanguages();
		$buffer='<select name="language">';
		
		foreach ($languages as $key => $value){
			if ($lang==$value){
				$buffer.='<option selected="selected" value="'.$value.'">'.$value.'</option>';
			}
			else{
				$buffer.='<option value="'.$value.'">'.$value.'</option>';
			}
		}
		$buffer.='</select>';
		return $buffer;
	}
	
}
?>