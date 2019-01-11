<?php


class HtpasswdEditor {
	private $users = [];

	private $filePath = '';

	public function createFiles ($folderPath, $htaccessContent) {
		file_put_contents($folderPath . '.htaccess', $htaccessContent);
		file_put_contents($folderPath . '.htpasswd', '');
	}

	public function read ($filePath) {
		if (!file_exists($filePath))
			return false;

		$file = fopen($filePath, 'r');

		while (!feof($file)) {
			$line = trim(fgets($file));

			if ($line === '')
				continue;

			preg_match('/(.+):(.+)/', $line, $matches);

			$this->users[$matches[1]] = $matches[2];
		}

		fclose($file);

		$this->filePath = $filePath;

		return true;
	}

	private function write () {
		$newFileData = '';

		foreach ($this->users as $username => $passwordHash) {
			$newFileData .= $username . ':' . $passwordHash . PHP_EOL;
		}

		return (file_put_contents($this->filePath, rtrim($newFileData)) !== false);
	}

	private function hashPassword ($password) {
		$salt = substr(str_shuffle("abcdefghijklmnopqrstuvwxyz0123456789"), 0, 8);
		$len = strlen($password);
		$text = $password . '$apr1$' . $salt;
		$tmp = '';
		$bin = pack("H32", md5($password . $salt . $password));
		for ($i = $len; $i > 0; $i -= 16) {
			$text .= substr($bin, 0, min(16, $i));
		}
		for ($i = $len; $i > 0; $i >>= 1) {
			$text .= ($i & 1) ? chr(0) : $password{0};
		}
		$bin = pack("H32", md5($text));
		for ($i = 0; $i < 1000; $i++) {
			$new = ($i & 1) ? $password : $bin;
			if ($i % 3) $new .= $salt;
			if ($i % 7) $new .= $password;
			$new .= ($i & 1) ? $bin : $password;
			$bin = pack("H32", md5($new));
		}
		for ($i = 0; $i < 5; $i++) {
			$k = $i + 6;
			$j = $i + 12;
			if ($j == 16) $j = 5;
			$tmp = $bin[$i] . $bin[$k] . $bin[$j] . $tmp;
		}
		$tmp = chr(0) . chr(0) . $bin[11] . $tmp;
		$tmp = strtr(strrev(substr(base64_encode($tmp), 2)),
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
			"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");

		return "$" . "apr1" . "$" . $salt . "$" . $tmp;
	}

	public function addUser ($username, $password) {
		if ($this->filePath === '')
			return false;

		if (isset($this->users[$username]))
			return false;

		$this->users[$username] = $this->hashPassword($password);

		return $this->write();
	}

	public function editUser ($oldUsername, $username, $password) {
		if ($this->filePath === '')
			return false;

		if (!isset($this->users[$oldUsername]))
			return false;

		$oldPasswordHash = $this->users[$oldUsername];
		unset($this->users[$oldUsername]);

		if ($password !== '') // If a new password was set, change it
			$this->users[$username] = $this->hashPassword($password);
		else
			$this->users[$username] = $oldPasswordHash;

		return $this->write();
	}

	public function removeUser ($username) {
		if ($this->filePath === '')
			return false;

		if (!isset($this->users[$username]))
			return false;

		unset($this->users[$username]);

		return $this->write();
	}

	public function getUsernames () {
		return array_keys($this->users);
	}
}


session_name('SherlockHomepage');
session_start();

$page = 'login';

$sherlockPassword = /*passwd*/'admin'/**/;

if (isset($_POST['password']) && $_POST['password'] === $sherlockPassword) {
	$_SESSION['loggedIn'] = true;
	$page = 'home';
}

if (isset($_SESSION['loggedIn']) && $_SESSION['loggedIn'] === true) {
	$page = 'home';
}

if (isset($_GET['setPassword'])) {
	$wrongPassword = false;

	if (isset($_POST['new_password']) && isset($_POST['old_password'])) {
		if ($sherlockPassword !== $_POST['old_password']) {
			$page = 'setPassword';
			$wrongPassword = true;
		}

		$thisFileData = file_get_contents(basename(__FILE__));

		$thisFileData = str_replace('/*passwd*/\'' . $_POST['old_password'] . '\'/**/', '/*passwd*/\'' . $_POST['new_password'] . '\'/**/', $thisFileData);

		file_put_contents(basename(__FILE__), $thisFileData);

		header('Location: SherlockHomepage.php');
	} else {
		$page = 'setPassword';
	}
}

if (isset($_GET['api'])) {
	$returnData = ['success' => false];

	switch ($_GET['api']) {
		case 'secureFolder':
			if (!isset($_GET['path']) || $_GET['path'] == '')
				break;

			if (!isset($_GET['username']) || $_GET['username'] == '')
				break;

			if (!isset($_GET['password']) || $_GET['password'] == '')
				break;

			$authUserFile = realpath('.' . $_GET['path'] . '/') . DIRECTORY_SEPARATOR . '.htpasswd';
			$htaccessContent = 'AuthUserFile ' . $authUserFile . '
AuthType Basic
AuthName "Password-Protected Area"
Require valid-user';

			$editor = new HtpasswdEditor();
			$editor->createFiles('.' . $_GET['path'] . '/', $htaccessContent);

			$success = $editor->read('.' . $_GET['path'] . '/.htpasswd');

			if (!$success)
				break;

			$success = $editor->addUser($_GET['username'], $_GET['password']);

			if (!$success)
				break;

			$returnData = ['success' => true];
			break;

		case 'secureFolderManually':
			if (!isset($_GET['path']) || $_GET['path'] == '')
				break;

			if (!isset($_GET['username']) || $_GET['username'] == '')
				break;

			if (!isset($_GET['password']) || $_GET['password'] == '')
				break;

			if (!isset($_GET['htaccess']) || $_GET['htaccess'] == '')
				break;

			$editor = new HtpasswdEditor();
			$editor->createFiles('.' . $_GET['path'] . '/', $_GET['htaccess']);

			$success = $editor->read('.' . $_GET['path'] . '/.htpasswd');

			if (!$success)
				break;

			$success = $editor->addUser($_GET['username'], $_GET['password']);

			if (!$success)
				break;

			$returnData = ['success' => true];
			break;

		case 'getHtaccessContent':
			if (!isset($_GET['path']) || $_GET['path'] == '')
				break;

			if (file_exists('.' . $_GET['path'] . '/.htaccess')) {
				$returnData = [
					'success' => true,
					'content' => file_get_contents('.' . $_GET['path'] . '/.htaccess'),
				];
			}
			break;

		case 'getHtpasswdUsers':
			if (!isset($_GET['path']) || $_GET['path'] == '')
				break;

			$editor = new HtpasswdEditor();
			$success = $editor->read('.' . $_GET['path'] . '/.htpasswd');

			if (!$success)
				break;

			$returnData = [
				'success' => true,
				'users'   => $editor->getUsernames(),
			];
			break;

		case 'addHtpasswdUser':
			if (!isset($_GET['path']) || $_GET['path'] == '')
				break;

			if (!isset($_GET['username']) || $_GET['username'] == '')
				break;

			if (!isset($_GET['password']) || $_GET['password'] == '')
				break;

			$editor = new HtpasswdEditor();
			$success = $editor->read('.' . $_GET['path'] . '/.htpasswd');

			if (!$success)
				break;

			$success = $editor->addUser($_GET['username'], $_GET['password']);

			if (!$success)
				break;

			$returnData = ['success' => true];
			break;

		case 'editHtpasswdUser':
			if (!isset($_GET['path']) || $_GET['path'] == '')
				break;

			if (!isset($_GET['old_username']) || $_GET['old_username'] == '')
				break;

			if (!isset($_GET['username']) || $_GET['username'] == '')
				break;

			if (!isset($_GET['password']))
				break;

			$editor = new HtpasswdEditor();
			$success = $editor->read('.' . $_GET['path'] . '/.htpasswd');

			if (!$success)
				break;

			$success = $editor->editUser($_GET['old_username'], $_GET['username'], $_GET['password']);

			if (!$success)
				break;

			$returnData = ['success' => true];
			break;

		case 'removeHtpasswdUser':
			if (!isset($_GET['path']) || $_GET['path'] == '')
				break;

			if (!isset($_GET['username']) || $_GET['username'] == '')
				break;

			$editor = new HtpasswdEditor();
			$success = $editor->read('.' . $_GET['path'] . '/.htpasswd');

			if (!$success)
				break;

			$success = $editor->removeUser($_GET['username']);

			if (!$success)
				break;

			$returnData = ['success' => true];
			break;

		case 'getAuthUserFilePath':
			if (!isset($_GET['path']) || $_GET['path'] == '')
				break;

			$returnData = [
				'path'    => realpath('.' . $_GET['path'] . '/') . DIRECTORY_SEPARATOR . '.htpasswd',
				'success' => true,
			];
			break;
	}

	header('Content-Type: application/json');
	die(json_encode($returnData));
}



function getDirTree ($path = '.') {
	$tree = [];

	$scanned = scandir($path);
	foreach ($scanned as $item) {
		if (!in_array($item, ['.', '..'])) {
			if (is_dir($path . DIRECTORY_SEPARATOR . $item)) {
				$htaccessExists = (file_exists($path . DIRECTORY_SEPARATOR . $item . '/.htaccess'));
				$htpasswdExists = (file_exists($path . DIRECTORY_SEPARATOR . $item . '/.htpasswd'));

				$tree[] = [
					'name'       => $item,
					'subfolders' => getDirTree($path . DIRECTORY_SEPARATOR . $item),
					'path'       => str_replace(DIRECTORY_SEPARATOR, '/', ltrim($path . DIRECTORY_SEPARATOR . $item, '.')),
					'htpasswd'   => $htpasswdExists,
					'htaccess'   => $htaccessExists,
				];
			}
		}
	}

	return $tree;
}

$tree = getDirTree();

?>

<!DOCTYPE html>
<html>
	<head>
		<meta charset="utf-8">
		<meta name="viewport" content="width=device-width, initial-scale=1">
		<title>Sherlock Homepage</title>
		<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bulma/0.7.2/css/bulma.min.css">
		<script defer src="https://use.fontawesome.com/releases/v5.3.1/js/all.js"></script>
		<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.3.1/jquery.min.js"></script>
	</head>
	<body>
		<section class="section">
			<div class="container">
				<h1 class="title">
					Sherlock Homepage
				</h1>
				<p class="subtitle">
					Don't let people access your private stuff!
				</p>

				<?php if ($page == 'login'): ?>
					<form method="post">
						<div class="field">
							<p class="control has-icons-left">
								<input name="password" class="input" type="password" placeholder="Password">
								<span class="icon is-small is-left">
									<i class="fas fa-lock"></i>
								</span>
							</p>
						</div>
						<div class="field is-grouped is-grouped-right">
							<p class="control">
								<button class="button is-success">
									Login
								</button>
							</p>
						</div>
					</form>
				<?php endif; ?>

				<?php if ($page == 'setPassword'): ?>
					<form method="post">
						<input type="hidden" name="setPassword" value="">
						<div class="field">
							<label class="label">Old Password:</label>
							<p class="control has-icons-left">
								<input name="old_password" class="input <?php if ($wrongPassword): ?>is-danger<?php endif; ?>" type="password" placeholder="Password">
								<span class="icon is-small is-left">
									<i class="fas fa-lock"></i>
								</span>
							</p>
							<p class="help">"admin" by default</p>
						</div>
						<div class="field">
							<label class="label">New Password:</label>
							<p class="control has-icons-left">
								<input name="new_password" class="input" type="password" placeholder="Password">
								<span class="icon is-small is-left">
									<i class="fas fa-lock"></i>
								</span>
							</p>
						</div>
						<div class="field is-grouped is-grouped-right">
							<p class="control">
								<button class="button is-success">
									Set Password
								</button>
							</p>
						</div>
					</form>
				<?php endif; ?>

				<?php if ($page == 'home'): ?>
					<div class="columns">
						<div class="column is-half">
							<nav class="panel" id="file-explorer">
								<p class="panel-heading">
									Explorer
								</p>
								<div class="panel-block">
									<p class="control has-icons-left">
										<input id="search" class="input is-small" type="text" placeholder="Search...">
										<span class="icon is-small is-left">
											<i class="fas fa-search" aria-hidden="true"></i>
										</span>
									</p>
								</div>
								<a class="panel-block" id="folder-up" style="display: none;">
									<span class="panel-icon">
										<i class="fas fa-folder" aria-hidden="true"></i>
									</span>
									..
								</a>
							</nav>
						</div>
						<div class="column is-half">
							<h4 class="title is-4">
								Folder: <code id="current-folder">/</code>
							</h4>

							<hr>

							<section id="secureFolder" style="display: none;">
								<div class="field">
									<p class="control has-icons-left">
										<input id="secureFolder-username" name="username" class="input" type="text" placeholder="Username">
										<span class="icon is-small is-left">
											<i class="fas fa-user"></i>
										</span>
									</p>
								</div>
								<div class="field">
									<p class="control has-icons-left">
										<input id="secureFolder-password" name="password" class="input" type="text" placeholder="Password">
										<span class="icon is-small is-left">
											<i class="fas fa-lock"></i>
										</span>
									</p>
								</div>
								<div class="field is-grouped is-grouped-right">
									<p class="control">
										<button id="secureFolder-submit" class="button is-warning">
											<span class="icon is-small is-left">
												<i class="fas fa-lock"></i>
											</span>
											<span>Secure this folder</span>
										</button>
									</p>
								</div>
							</section>

							<section id="secureFolderManually" style="display: none;">
								<div class="field">
									<p class="control has-icons-left">
										<input id="secureFolderManually-username" name="username" class="input" type="text" placeholder="Username">
										<span class="icon is-small is-left">
											<i class="fas fa-user"></i>
										</span>
									</p>
								</div>
								<div class="field">
									<p class="control has-icons-left">
										<input id="secureFolderManually-password" name="password" class="input" type="text" placeholder="Password">
										<span class="icon is-small is-left">
											<i class="fas fa-lock"></i>
										</span>
									</p>
								</div>

								<div class="box">
									<p>
										There is already an .htaccess file in this directory!<br />
										You have to edit the .htaccess file manually, in order to prevent mistakes.<br />
										Here's the code to paste:
									</p>
									<br />
									<div class="has-background-light has-text-danger" style="padding: .25em .5em .25em; font-weight: 400; font-size: .875em; font-family: monospace; overflow-x: auto; overflow-y: hidden; white-space: nowrap;">
										<span id="authUserFile">AuthUserFile</span><br />
										AuthType Basic<br />
										AuthName "Password-Protected Area"<br />
										Require valid-user<br />
									</div>
								</div>

								<div class="field">
									<div class="control">
										<textarea
												rows="8"
												style="font-family: monospace;     white-space: pre;"
												id="secureFolderManually-htaccess"
												class="textarea"
												placeholder=".htaccess...">
										</textarea>
									</div>
								</div>

								<div class="field is-grouped is-grouped-right">
									<p class="control">
										<button class="button is-warning" id="secureFolderManually-submit">
											<span class="icon is-small is-left">
												<i class="fas fa-lock"></i>
											</span>
											<span>Secure this folder</span>
										</button>
									</p>
								</div>
							</section>

							<section id="editFolder" style="display: none;">
								<h6 class="title is-6">This folder is <b>secured</b>.</h6>

								<table class="table is-fullwidth is-hoverable">
									<thead>
										<th>Username</th>
										<th>Password</th>
										<th></th>
									</thead>
									<tbody id="htpasswd-users">
									</tbody>
								</table>

								<button class="button is-success" id="add-user">
									<span class="icon is-small is-left">
										<i class="fas fa-plus"></i>
									</span>
									<span>Add User</span>
								</button>

								<button id="remove-protection" class="button is-text has-text-danger" style="float: right;">
									Remove protection from this folder
								</button>

								<div class="modal" id="add-user-modal">
									<div class="modal-background"></div>
									<div class="modal-card">
										<header class="modal-card-head">
											<p class="modal-card-title">Add User</p>
											<button class="modal-close-btn delete" aria-label="close"></button>
										</header>
										<section class="modal-card-body">
											<div class="field">
												<p class="control has-icons-left">
													<input id="add-user-username" name="username" class="input" type="text" placeholder="Username">
													<span class="icon is-small is-left">
														<i class="fas fa-user"></i>
													</span>
												</p>
											</div>
											<div class="field">
												<p class="control has-icons-left">
													<input id="add-user-password" name="password" class="input" type="text" placeholder="Password">
													<span class="icon is-small is-left">
														<i class="fas fa-lock"></i>
													</span>
												</p>
											</div>

											<div class="field is-grouped is-grouped-right">
												<div class="control">
													<button class="modal-cancel-btn button">Cancel</button>
												</div>
												<div class="control">
													<button class="button is-success" id="add-user-submit">
														<span class="icon is-small is-left">
															<i class="fas fa-plus"></i>
														</span>
														<span>Add User</span>
													</button>
												</div>
											</div>
										</section>
									</div>
								</div>

								<div class="modal" id="edit-user-modal">
									<div class="modal-background"></div>
									<div class="modal-card">
										<header class="modal-card-head">
											<p class="modal-card-title">Edit User - <span id="edit-user-currusername"></span></p>
											<button class="modal-close-btn delete" aria-label="close"></button>
										</header>
										<section class="modal-card-body">
											<div class="field">
												<p class="control has-icons-left">
													<input id="edit-user-username" name="username" class="input" type="text" placeholder="Username">
													<span class="icon is-small is-left">
														<i class="fas fa-user"></i>
													</span>
												</p>
											</div>
											<div class="field">
												<p class="control has-icons-left">
													<input id="edit-user-password" name="password" class="input" type="text" placeholder="New Password">
													<span class="icon is-small is-left">
														<i class="fas fa-lock"></i>
													</span>
												</p>
												<p class="help">Leave empty if you don't want to change it</p>
											</div>

											<div class="field is-grouped is-grouped-right">
												<div class="control" style="flex-grow: 1;">
													<button class="button is-danger" id="edit-user-remove">
														<span class="icon is-small is-left">
															<i class="fas fa-trash"></i>
														</span>
														<span>Remove</span>
													</button>
												</div>
												<div class="control">
													<button class="modal-cancel-btn button">Cancel</button>
												</div>
												<div class="control">
													<button class="button is-success" id="edit-user-submit">
														<span class="icon is-small is-left">
															<i class="fas fa-save"></i>
														</span>
														<span>Save</span>
													</button>
												</div>
											</div>
										</section>
									</div>
								</div>

							</section>
						</div>
					</div>

					<script type="text/javascript">
						const folderTree = JSON.parse('<?= json_encode($tree); ?>');
						let currFolder = {
							root:       true,
							subfolders: folderTree,
							path:       '/',
							htaccess:   false,
							htpasswd:   false
						};

						$(document).ready(() => {
							$('#folder-up').click(function (event) {
								if (currFolder.root) {
									return;
								}

								currFolder = currFolder.upperFolder;
								showCurrFolder();
							});

							$('#secureFolder-submit').click(function (event) {
								if ($('#secureFolder-username').val() === '') {
									$('#secureFolder-username').addClass('is-danger');
									return;
								}

								if ($('#secureFolder-password').val() === '') {
									$('#secureFolder-password').addClass('is-danger');
									return;
								}

								$('#secureFolder-submit').addClass('is-loading');

								$.getJSON('SherlockHomepage.php', {
									api:      'secureFolder',
									path:     currFolder.path,
									username: $('#secureFolder-username').val(),
									password: $('#secureFolder-password').val()
								}).done(response => {
									if (response.success) {
										window.location.reload();
									} else {
										alert('An error occured while securing folder!');
										$('#secureFolder-submit').removeClass('is-loading');
									}
								}).fail(msg => {
									console.error(msg);
									alert('An error occured while securing folder!');
									$('#secureFolder-submit').removeClass('is-loading');
								});
							});

							$('#secureFolderManually-submit').click(function (event) {
								if ($('#secureFolderManually-username').val() === '') {
									$('#secureFolderManually-username').addClass('is-danger');
									return;
								}

								if ($('#secureFolderManually-password').val() === '') {
									$('#secureFolderManually-password').addClass('is-danger');
									return;
								}

								$('#secureFolderManually-submit').addClass('is-loading');

								$.getJSON('SherlockHomepage.php', {
									api:      'secureFolderManually',
									path:     currFolder.path,
									username: $('#secureFolderManually-username').val(),
									password: $('#secureFolderManually-password').val(),
									htaccess: $('#secureFolderManually-htaccess').val()
								}).done(response => {
									if (response.success) {
										window.location.reload();
									} else {
										alert('An error occured while securing folder!');
										$('#secureFolderManually-submit').removeClass('is-loading');
									}
								}).fail(msg => {
									console.error(msg);
									alert('An error occured while securing folder!');
									$('#secureFolderManually-submit').removeClass('is-loading');
								});
							});

							$('#remove-protection').click(function (event) {
								alert('Not yet implemented!');
								$('#remove-protection-modal').addClass('is-active');
							});

							$('#add-user').click(function (event) {
								$('#add-user-modal').addClass('is-active');
							});

							$('#add-user-submit').click(function (event) {
								if ($('#add-user-username').val() === '') {
									$('#add-user-username').addClass('is-danger');
									return;
								}

								if ($('#add-user-password').val() === '') {
									$('#add-user-password').addClass('is-danger');
									return;
								}

								$('#add-user-submit').addClass('is-loading');

								$.getJSON('SherlockHomepage.php', {
									api:      'addHtpasswdUser',
									path:     currFolder.path,
									username: $('#add-user-username').val(),
									password: $('#add-user-password').val()
								}).done(response => {
									if (response.success) {
										$('#add-user-submit').removeClass('is-loading');
										$('#add-user-modal').removeClass('is-active');
										updateUsersList();

										$('#add-user-username').val('');
										$('#add-user-password').val('');
									} else {
										alert('An error occured while adding .htpasswd user!');
										$('#add-user-submit').removeClass('is-loading');
									}
								}).fail(msg => {
									console.error(msg);
									alert('An error occured while adding .htpasswd user!');
									$('#add-user-submit').removeClass('is-loading');
								});
							});

							$('#edit-user-remove').click(function (event) {
								let username = $('#edit-user-currusername').text();

								let confirmed = confirm('Are you sure you want to remove user "' + username + '"');

								if (confirmed) {
									$('#edit-user-remove').addClass('is-loading');

									$.getJSON('SherlockHomepage.php', {
										api:      'removeHtpasswdUser',
										path:     currFolder.path,
										username: username
									}).done(response => {
										if (response.success) {
											$('#edit-user-remove').removeClass('is-loading');
											$('#edit-user-modal').removeClass('is-active');
											updateUsersList();
										} else {
											alert('An error occured while removing .htpasswd user!');
										}
									}).fail(msg => {
										console.error(msg);
										alert('An error occured while removing .htpasswd user!');
									});
								}
							});

							$('#edit-user-submit').click(function (event) {
								if ($('#edit-user-username').val() === '') {
									$('#edit-user-username').addClass('is-danger');
									return;
								}

								$('#edit-user-submit').addClass('is-loading');

								$.getJSON('SherlockHomepage.php', {
									api:          'editHtpasswdUser',
									path:         currFolder.path,
									username:     $('#edit-user-username').val(),
									password:     $('#edit-user-password').val(),
									old_username: $('#edit-user-currusername').text()
								}).done(response => {
									if (response.success) {
										$('#edit-user-submit').removeClass('is-loading');
										$('#edit-user-modal').removeClass('is-active');
										updateUsersList();

										$('#edit-user-username').val('');
										$('#edit-user-password').val('');
									} else {
										alert('An error occured while adding .htpasswd user!');
										$('#edit-user-submit').removeClass('is-loading');
									}
								}).fail(msg => {
									console.error(msg);
									alert('An error occured while adding .htpasswd user!');
									$('#edit-user-submit').removeClass('is-loading');
								});
							});

							$('.modal-cancel-btn, .modal-close-btn, .modal-background').click(function (event) {
								$('.modal').removeClass('is-active');
							});

							showCurrFolder();
						});

						function showCurrFolder() {
							if (currFolder.root) {
								$('#folder-up').hide();
							} else {
								$('#folder-up').show();
							}

							$('.folder').remove();

							currFolder.subfolders.forEach(subfolder => {
								let displayLock = subfolder.htpasswd ? 'inherit' : 'none';

								$('#file-explorer').append(
									`
								<a class="panel-block folder">
									<span class="panel-icon">
										<i class="fas fa-folder" aria-hidden="true"></i>
									</span>

									${subfolder.name}

									<span class="panel-icon" style="display: inherit; flex: 1; flex-direction: row-reverse; display: ${displayLock};">
										<i class="fas fa-lock" aria-hidden="true"></i>
									</span>
								</a>
								`
								);


							});

							$('.folder').click(function (event) {
								currFolder.subfolders.forEach(subfolder => {
									if (subfolder.name === event.currentTarget.text.trim()) {
										subfolder.upperFolder = currFolder;
										currFolder = subfolder;
										showCurrFolder();
									}
								});
							});

							$('#current-folder').text(currFolder.path);


							if (!currFolder.htpasswd && !currFolder.htaccess) {
								$('#secureFolder').show();
								$('#secureFolderManually').hide();
								$('#editFolder').hide();
							} else if (!currFolder.htpasswd && currFolder.htaccess) {
								$.getJSON('SherlockHomepage.php', {
									api:  'getHtaccessContent',
									path: currFolder.path
								}).done(response => {
									if (response.success) {
										$('#secureFolderManually-htaccess').val(response.content);
									} else {
										alert('An error occured while fetching .htaccess content!');
									}
								}).fail(msg => {
									console.error(msg);
									alert('An error occured while fetching .htaccess content!');
								});

								$.getJSON('SherlockHomepage.php', {
									api:  'getAuthUserFilePath',
									path: currFolder.path
								}).done(response => {
									if (response.success) {
										$('#authUserFile').text('AuthUserFile ' + response.path);
									} else {
										alert('An error occured while fetching auth user file path!');
									}
								}).fail(msg => {
									console.error(msg);
									alert('An error occured while fetching auth user file path!');
								});


								$('#secureFolder').hide();
								$('#secureFolderManually').show();
								$('#editFolder').hide();
							} else if (currFolder.htpasswd && currFolder.htaccess) {
								updateUsersList();

								$('#secureFolder').hide();
								$('#secureFolderManually').hide();
								$('#editFolder').show();
							}
						}

						function updateUsersList() {
							$.getJSON('SherlockHomepage.php', {
								api:  'getHtpasswdUsers',
								path: currFolder.path
							}).done(response => {
								if (response.success) {
									$('#htpasswd-users').empty();

									response.users.forEach(username => {
										$('#htpasswd-users').append(
											`
											<tr>
												<td>${username}</td>
												<td>&#183;&#183;&#183;&#183;&#183;&#183;&#183;</td>
												<td>
													<button id="${username}" class="button is-warning edit-user" style="float: right;">
														<span class="icon is-small is-left">
															<i class="fas fa-edit"></i>
														</span>
														<span>Edit</span>
													</button>
												</td>
											</tr>
											`
										);
									});

									$('.edit-user').click(function (event) {
										let username = event.currentTarget.id;

										$('#edit-user-currusername').text(username);
										$('#edit-user-username').val(username);
										$('#edit-user-modal').addClass('is-active');
									});
								} else {
									alert('An error occured while fetching .htaccess content!');
								}
							}).fail(msg => {
								console.error(msg);
								alert('An error occured while fetching .htaccess content!');
							});
						}
					</script>
				<?php endif; ?>
			</div>
		</section>
	</body>
</html>