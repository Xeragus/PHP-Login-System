<?php
require_once 'config.php';

$username = $password = $password_confirm = "";
$username_err = $password_err = $password_confirm_err = "";

if($_SERVER["REQUEST_METHOD"] == "POST") {
  if(empty(trim($_POST["username"]))) {
    $username_err = "Please enter your username.";
  } else {
    $sql = "SELECT id FROM users WHERE username = ?";

    if($stmt = mysqli_prepare($link, $sql)) {
      mysqli_stmt_bind_param($stmt, "s", $username_param);

      $username_param = trim($_POST["username"]);

      if(mysqli_stmt_execute($stmt)) {
        mysqli_stmt_store_result($stmt);

        if(mysqli_stmt_num_rows($stmt) == 1) {
          $username_err = "This username is already taken.";
        } else {
          $username = trim($_POST["username"]);
        }
      } else {
        echo "Something went wrong. Please try again later.";
      }
    }
    mysqli_stmt_close($stmt);
  }

  if(empty(trim($_POST["password"]))) {
    $password_err = "Please enter a password";
  } elseif (strlen(trim($_POST["password"])) < 6) {
    $password_err = "The password must have at least 6 characters.";
  } else {
    $password = trim($_POST["password"]);
  }

  if(empty(trim($_POST["password_confirm"]))) {
    $password_confirm_err = "Please confirm your password.";
  } else {
    $password_confirm = trim($_POST["password_confirm"]);
    if($password != $password_confirm) {
      $password_confirm_err = "Passwords do not match.";
    }
  }

  // check for errors before inserting in the database
  if(empty($username_err) && empty($password_err) && empty($password_confirm_err)) {
    $sql = "INSERT INTO users (username, password) VALUES (?, ?)";

    if($stmt = mysqli_prepare($link, $sql)) {
       mysqli_stmt_bind_param($stmt, "ss", $param_username, $param_password);
       $param_username = $username;
       $param_password = password_hash($password, PASSWORD_DEFAULT);

       if(mysqli_stmt_execute($stmt)) {
        header("location: login.php");
       } else {
          echo "Something went wrong. Try again.";
       }
    }
    mysqli_stmt_close($stmt);
  }
  mysqli_close($link);
}

?>

<!doctype html>
<html lang="en">
  <head>
    <!-- Required meta tags -->
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">

    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">

    <title>Register</title>
  </head>
  <body>

    <div class="container">
      <h2>Sign Up</h2>
      <p>Please fill out this form to create an account.</p>
      <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post">
        <div class="form-group <?php echo (!empty($username_err)) ? 'custom-password-error' : ''; ?>">
          <label for="username">Username</label>
          <input type="text" name="username" class="form-control" id="username">
          <span class="form-text"><?php echo $username_err; ?></span>
        </div>
        <div class="form-group <?php echo (!empty($password_err)) ? 'custom-password-error' : ''; ?>">
          <label for="#password">Password</label>
          <input type="password" class="form-control" name="password" id="password">
          <span class="form-text"><?php echo $username_err; ?></span>
        </div>
        <div class="form-group <?php echo (!empty(password_confirm_err)) ? 'custom-password-error' : ''; ?>">
          <label for="#password_confirm">Confirm Password</label>
          <input type="password" id="password_confirm" name="password_confirm" class="form-control" value="<?php echo $password_confirm ?>" id="passwordConfirm">
          <span class="form-text"><?php echo $username_err; ?></span>
        </div>
        <button type="submit" class="btn btn-primary">Submit</button>
        <button type="reset" class="btn btn-default">Reset</button>
        <br>
        <p>Have an account?<a href="login.php">Login here</a>.</p>

      </form>
    </div>

    <!-- Optional JavaScript -->
    <!-- jQuery first, then Popper.js, then Bootstrap JS -->
    <script src="https://code.jquery.com/jquery-3.2.1.slim.min.js" integrity="sha384-KJ3o2DKtIkvYIK3UENzmM7KCkRr/rE9/Qpg6aAZGJwFDMVNA/GpGFF93hXpG5KkN" crossorigin="anonymous"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.12.9/umd/popper.min.js" integrity="sha384-ApNbgh9B+Y1QKtv3Rn7W3mgPxhU9K/ScQsAP7hUibX39j7fakFPskvXusvfa0b4Q" crossorigin="anonymous"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/js/bootstrap.min.js" integrity="sha384-JZR6Spejh4U02d8jOt6vLEHfe/JQGiRRSQQxSfFWpi1MquVdAyjUar5+76PVCmYl" crossorigin="anonymous"></script>
  </body>
</html>