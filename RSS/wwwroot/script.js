console.log("Script loaded");
document.querySelector('#regForm').addEventListener('submit', async function (event) {
    console.log("entred");
    event.preventDefault();

    const formData = new FormData(this); // Get form data

    const response = await fetch('/add-user', {
        method: 'POST',
        body: formData
    });

    const responseData = await response.json();
    if (responseData && responseData.message === "user already exists") {
        const errorMessage = document.getElementById('errorMessage');
        if (errorMessage) {
            // Update existing error message
            errorMessage.innerHTML = `<h6>Email already exists! Please use a different email.</h6>`;
        } else {
            // Create new error message
            const newErrorMessage = document.createElement('div');
            newErrorMessage.id = 'errorMessage';
            newErrorMessage.classList.add('text-dark', 'mt-2', 'col-md-12');
            newErrorMessage.innerHTML = `<h6>Email already exists! Please use a different email.</h6>`;

            // Append the message element to the modal body
            const modalBody = document.getElementById('errormsg');
            modalBody.appendChild(newErrorMessage);
        }
    } else {
        // Process the response
        // After successful registration, show the success modal
        var successModal = new bootstrap.Modal(document.getElementById('successModal'));
        successModal.show();

        this.reset();
        const errorMessage = document.getElementById('errorMessage');
        if (errorMessage) {
            errorMessage.remove();
        }
    }
});

const closeReg = document.getElementById('closereg');
const form = document.getElementById('regForm');

// Add event listener to the close button
closeReg.addEventListener('click', function (event) {
    // Reset the form
    form.reset();
    const errorMessage = document.getElementById('errorMessage');
    if (errorMessage) {
        errorMessage.remove();
    }
});