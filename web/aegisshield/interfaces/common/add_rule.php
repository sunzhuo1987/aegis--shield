<?php
if ($_POST['send']=="Add rule"){
		$rule_array=array('rule'=>$_POST['rule'], 'type'=>$_POST['type'], 'proto'=>$_POST['proto']);
		
		print_r($rule_array);
		echo '<div class="submit_form">'.$RULE->add_rule($rule_array).'</div>';
}
else{
?>

<h4><?php echo "Add rule"; ?></h4>
<form method="post" action="">
<table id="add_rule" class="default_table">
  <tr>
    <td><?php echo "rule"; ?> * </td>
    <td><input type="text" name="rule" /></td>
  </tr>
  <tr>
  	<td><?php echo "type"; ?> * </td>
  	<td><select name="type">
  	<option selected = "selected" value = "1">snort</option>
  	<option value = "2">L7</option>
  	</select></td>
  </tr>
  <tr>
  	<td><?php echo "proto"; ?></td>
  	<td><input type="text" name="proto"/></td>
  </tr>
  <tr>
  	<td>
  		<input type="submit" name="send" value="Add rule"></input>
  	</td>
  </tr>
</table>
</form>
<br />

<?php 
}
?>