<!DOCTYPE html>
<html>
<head>
    <title>Submission Result</title>
    <style>
        body {
            background-color: #4e8c9e; /* Soothing teal color for the background */
            color: white;
            font-family: 'Helvetica Neue', sans-serif; /* Modern and clean font */
            margin: 0;
            padding: 20px;
            text-align: center; /* Center aligning the content */
        }
        h1 {
            color: #ffeb3b; /* Bright yellow for the heading */
        }
        .response {
            background-color: #ffffff; /* White background for response */
            padding: 20px;
            border-radius: 15px; /* Rounded corners for the response box */
            display: inline-block; /* Center the response box */
            margin-top: 20px;
            color: #333333; /* Dark text color for readability */
        }
        .back-button {
            padding: 10px 20px;
            background-color: #007bff; /* Cool blue color for the button */
            color: #ffffff;
            border: none;
            border-radius: 25px; /* Rounded corners for the button */
            font-size: 16px;
            font-weight: bold;
            box-shadow: 0 4px 8px 0 rgba(0,0,0,0.2); /* Subtle shadow for depth */
            transition: all 0.3s;
            text-decoration: none; /* Remove underline from link */
            margin-top: 20px; /* Space above the button */
        }
        .back-button:hover {
            background-color: #0056b3; /* Darker blue on hover */
            box-shadow: 0 6px 12px 0 rgba(0,0,0,0.3);
        }
    </style>
</head>
<body>
    <h1>POST Submission Result</h1>
    <div class="response">
    <?php
        if (isset($_POST['club_name']) && isset($_POST['country_name'])) {
            echo "This is your Favorite Team!<br>"; // Line break after "Hello"
            echo "Team: " . htmlspecialchars($_POST['club_name']) . "<br>"; // Prepend "Team" before club_name
            echo "Country: " . htmlspecialchars($_POST['country_name']); // Prepend "Country" before country_name
        } else {
            echo "No data received.";
        }
    ?>
</div>
<a href="index.html" class="back-button">Go Back Home</a> <!-- Back home button -->
</body>
</html>

