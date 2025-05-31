function saveResume() {
    const formData = new FormData();
    
    formData.append('professional_summary', document.getElementById('professional-summary').value);
    
    document.querySelectorAll('.skill-tag').forEach((tag, index) => {
        formData.append(`skills[${index}]`, tag.querySelector('span').textContent);
    });
    
    document.querySelectorAll('#projects-container .item-card').forEach((card, index) => {
        formData.append(`project_name[${index}]`, card.querySelector('input[name="project_name"]').value);
        formData.append(`project_type[${index}]`, card.querySelector('select[name="project_type"]').value);
        formData.append(`duration[${index}]`, `${card.querySelector('input[name="duration_start"]').value}-${card.querySelector('input[name="duration_end"]').value}`);
        formData.append(`description[${index}]`, card.querySelector('textarea[name="description"]').value);
        formData.append(`github_link[${index}]`, card.querySelector('input[name="github_link"]').value);
    });
    
    document.querySelectorAll('#certifications-container .item-card').forEach((card, index) => {
        formData.append(`certification_name[${index}]`, card.querySelector('input[name="certification_name"]').value);
        formData.append(`issuer[${index}]`, card.querySelector('input[name="issuer"]').value);
        formData.append(`cert_duration[${index}]`, `${card.querySelector('input[name="cert_duration_start"]').value}-${card.querySelector('input[name="cert_duration_end"]').value}`);
        formData.append(`credential_id[${index}]`, card.querySelector('input[name="credential_id"]').value);
    });
    
    const resumeFile = document.getElementById('resume-file').files[0];
    if (resumeFile) formData.append('resume', resumeFile);
    
    fetch('/profile', {
        method: 'POST',
        body: formData,
        headers: { 'X-Requested-With': 'XMLHttpRequest' }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert('Resume saved successfully!');
            window.location.href = '/dashboard';
        } else {
            alert('Error saving resume: ' + data.error);
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('An error occurred while saving the resume.');
    });
}