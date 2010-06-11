<h4><?php echo $admin[49]; ?></h4>

<?php
switch($_GET['type']){
	case 'configure':
	
		if ($_POST['send']==$admin[35]){
			$group_array=array('id'=>$_GET['id'], 'name'=>$_POST['name'], 'description'=>$_POST['description']);
			echo '<div class="submit_form">'.$GROUP->set_group($group_array).'</div>';
		}
		else{
?>

<h5><?php echo $admin[78]; ?></h5>
<?php
$group_selected=$GROUP->get_group($_GET['id']);
?>
<form method="post" action="">
<table id="change_group" class="default_table">
  <tr>
    <td><?php echo $admin[11]; ?> * </td>
    <td><input type="text" name="name" value="<?php echo htmlspecialchars($group_selected['name']); ?>" /></td>
  </tr>
  <tr>
    <td><?php echo $admin[50]; ?></td>
    <td><textarea name="description" rows="" cols=""><?php echo htmlspecialchars($group_selected['description']); ?></textarea></td>
  </tr>
  <tr>
    <td>&nbsp;</td>
    <td><input type="submit" name="send" value="<?php echo $admin[35]; ?>" /></td>
  </tr>
</table>
</form>

<?php
		}
	break;
	case 'delete':
		if ($_POST['send']==$admin[33]){
			echo '<div class="submit_form">'.$GROUP->del_group($_GET['id']).'</div>';
		}
		elseif($_POST['send']==$admin[34]){
			echo '<div class="submit_form">'.$admin[101].'</div>';
		}
		else{
?>

<h5><?php echo $admin[77]; ?></h5>
<form method="post" action="">
<table id="delete_group" class="default_table">
<tr class="center"><td><input type="submit" name="send" value="<?php echo $admin[33]; ?>" /></td><td><input type="submit" name="send" value="<?php echo $admin[34]; ?>" /></td>
</tr></table>
</form>

<?php
		}
	break;
	case 'view':
?>

<?php
$group_selected=$GROUP->get_group($_GET['id']);
?>
<h5><?php echo $admin[76]; ?></h5>
<table id="view_group" class="default_table">
  <tr>
    <td><?php echo $admin[11]; ?></td>
    <td><?php echo htmlspecialchars($group_selected['name']); ?></td>
  </tr>
  <tr>
    <td><?php echo $admin[50]; ?></td>
    <td><?php echo htmlspecialchars($group_selected['description']); ?></td>
  </tr>
</table>

<?php
	break;
	default:
?>
<table id="manage_group" class="default_table">
  <tr>
    <th><?php echo $admin[11]; ?></th>
    <th><?php echo $admin[50]; ?></th>
	<th><?php echo $admin[60]; ?></th>
  </tr>
<?php
	$groups_id=$GROUP->get_groups_id();
	foreach($groups_id as $value){
		$group_selected=$GROUP->get_group($value['id']);
		echo '<tr><td>'.htmlspecialchars($group_selected['name']).'</td><td>'.htmlspecialchars($group_selected['description']).'</td><td>'.$GROUP->option_list($group_selected['id']).'</td></tr>';
	}
?>
</table>

<?php
}
?>