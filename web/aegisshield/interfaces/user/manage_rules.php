<?php 
	/*ag_rules
	 * id | type  | rule | proto
	 */
?>


<h4><?php echo "RULES MANAGEMETN"; ?></h4>

<?php 
	

switch($_GET['type']){
	/*
	 * 添加规则
	 */
	case 'add_rule':
		require_once('interfaces/user/add_rule.php');
?>
<table>
</table>
<?php 
		break;
		
	/*
	 * 删除规则
	 */
	case 'delete_rule':
		if ($_POST['send']==/*$admin[33]*/"Yes"){
			echo '<div class="submit_form">'.$RULE->del_rule($_GET['id']).'</div>';
		}
		elseif($_POST['send']==/*$admin[34]*/"No"){
			echo '<div class="submit_form">'.'Not Deleted!'.'</div>';
		}
		else{
	/*
	 * 删除确认
	 */
?>

<h5><?php echo /*$admin[68]*/'Are you sure to delete this rule?'; ?></h5>
<form method="post" action="">
<table id="delete_rule" class="default_table">
<tr class="center"><td><input type="submit" name="send" value="<?php echo /*$admin[33]*/"Yes"; ?>" /></td><td><input type="submit" name="send" value="<?php echo /*$admin[34]*/'No'; ?>" /></td>
</tr></table>
</form>

<?php
		}
	break;
	case 'change_rule':
		if ($_POST['send']=='Update'){
			echo '<div class="submit_form">'.$RULE->change_rule($_GET['id'], $_POST['rule']).'</div>';
		}
		else{
?>

<h5><?php echo 'Change Rule'; ?></h5>
<form method="post" action="">
<table id="change_rule" class="default_table">
<tr class="center"><td><input type="text" name="rule" value="" /></td></tr>
<tr class="center"><td><input type="submit" name="send" value="<?php echo 'Update'; ?>" /></td>
</tr>
</table>
</form>

<?php
		}
	break;
	default:
		/*
		 * 显示数据库中的规则
		 */
?>
<table id="manage_rule" class="default_table">
  <tr>
	<th>&nbsp;</th>
    <th><?php echo 'Rules'; ?></th>
  
  </tr>
<?php
	$rules_id=$RULE->get_rules_id();
	$count = 0;
	foreach($rules_id as $value){
		$rule_selected=$RULE->get_rule($value['id']);
		$count++;
		echo '<tr><td>##'.$count.
		'</td><td>'.htmlspecialchars($rule_selected['rule']).
		'</td><td>'.$RULE->option_list_user($rule_selected['id']).
		'</td></tr>';
	}
?>
<tr><td>
<a href="user.php?action=manage_rules&type=add_rule"><img src="images/add.png", alt="Add rule", title="Add rule" /></a>
</td></tr>
</table>

<?php
}
?>