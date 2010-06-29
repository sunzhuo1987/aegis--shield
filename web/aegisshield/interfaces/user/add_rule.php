<?php
if ($_POST['send']==$admin[483]){
		$rule_array=array('rule'=>$_POST['rule'], 'type'=>$_POST['type'], 'proto'=>$_POST['proto']);
		
		print_r($rule_array);
		echo '<div class="submit_form">'.$RULE->add_rule($rule_array).'</div>';
}
else{
?>

<h4><?php echo $admin[483]; ?></h4>
<form method="post" action="">
<table id="add_rule" class="default_table">
  <tr>
    <td><?php echo $admin[480]; ?> * </td>
    <td><input type="text" name="rule" /></td>
  </tr>
  <tr>
  	<td><?php echo $admin[481]; ?> * </td>
  	<td><select name="type">
  	<option selected = "selected" value = "1"><?php echo $admin[484];?></option>
  	<option value = "2"><?php echo $admin[485];?></option>
  	</select></td>
  </tr>
  <tr>
  	<td><?php echo $admin[482]; ?></td>
  	<td><input type="text" name="proto"/></td>
  </tr>
  <tr>
  	<td>
  		<input type="submit" name="send" value="<?php echo $admin[483];?>"></input>
  	</td>
  </tr>
</table>
</form>
<br />

<?php 
}
?>