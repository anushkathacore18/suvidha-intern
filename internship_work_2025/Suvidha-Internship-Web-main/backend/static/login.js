document.addEventListener('DOMContentLoaded', function () {
  // Update hidden role input when userType changes
  const radioButtons = document.querySelectorAll('input[name="userType"]');
  const roleInput = document.getElementById('role');
  const signupLink = document.getElementById('signup-link');
  const loginForm = document.querySelector('form');
  const usernameInput = document.querySelector('input[name="username"]');

  if (!roleInput || !signupLink || !loginForm || !usernameInput) {
    console.error('Required elements not found');
    return;
  }

  radioButtons.forEach(radio => {
    radio.addEventListener('change', function () {
      const selectedRole = this.value;
      roleInput.value = selectedRole;
      console.log("Selected role:", selectedRole);
    });
  });

  // Handle Sign Up link click
  signupLink.addEventListener('click', function (e) {
    e.preventDefault();
    const selectedRole = document.querySelector('input[name="userType"]:checked')?.value;
    if (!selectedRole) {
      console.error('No role selected');
      alert('Please select a role (Student, Employee, or TPO).');
      return;
    }
    window.location.href = `/register/${selectedRole}`;
  });

  // Optional: Client-side validation for username/email
  loginForm.addEventListener('submit', function (e) {
    const identifier = usernameInput.value.trim();
    // Simple regex to check if input is an email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const isEmail = emailRegex.test(identifier);
    const isUsername = /^[a-zA-Z0-9_]{3,}$/.test(identifier); // Example: username must be 3+ chars, alphanumeric or underscore

    if (!isEmail && !isUsername) {
      e.preventDefault();
      alert('Please enter a valid username (3+ characters, alphanumeric or underscore) or email address.');
      return;
    }
  });

  // Button animation on click
  const loginButton = document.querySelector('button');
  if (loginButton) {
    loginButton.addEventListener('click', function () {
      this.style.animation = 'success-glow 0.5s ease';
      setTimeout(() => {
        this.style.animation = '';
      }, 500);
    });
  }
});