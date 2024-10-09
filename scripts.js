// Get the popups and the links to open them
const signupPopup = document.getElementById('signup-popup');
const confirmEmailPopup = document.getElementById('confirm-email-popup');
const signupLink = document.getElementById('signup-link');
const closePopup = document.getElementById('close-popup');
const closeConfirmPopup = document.getElementById('close-confirm-popup');
const nextButton = document.getElementById('next-button');
const reviewDetailsLink = document.getElementById('review-details-link');

// Open the signup popup when the SIGN UP link is clicked
signupLink.onclick = function() {
    signupPopup.style.display = 'block'; // Show the signup popup
}

// Close the signup popup when the close button is clicked
closePopup.onclick = function() {
    signupPopup.style.display = 'none'; // Hide the signup popup
}

// Close the confirm email popup when the close button is clicked
closeConfirmPopup.onclick = function() {
    confirmEmailPopup.style.display = 'none'; // Hide the confirm email popup
}

// Open the confirm email popup when the Next button is clicked
nextButton.onclick = function() {
    confirmEmailPopup.style.display = 'block'; // Show the confirm email popup
    signupPopup.style.display = 'none'; // Hide the signup popup
}

// Navigate to signup_complete.html when Sign Up button is clicked
const signUpButton = document.querySelector('#confirm-email-popup button');
signUpButton.onclick = function() {
    window.location.href = 'signup_complete.html'; // Redirect to signup complete page
};

// Return to the signup popup when the Review Your Details link is clicked
reviewDetailsLink.onclick = function() {
    confirmEmailPopup.style.display = 'none'; // Hide the confirm email popup
    signupPopup.style.display = 'block'; // Show the signup popup
}

// Close the confirm email popup if the user clicks outside of it
window.onclick = function(event) {
    if (event.target === signupPopup) {
        signupPopup.style.display = 'none'; // Hide the signup popup
    }
    if (event.target === confirmEmailPopup) {
        confirmEmailPopup.style.display = 'none'; // Hide the confirm email popup
    }
}
