// extra.js
// document.addEventListener('DOMContentLoaded', () => {
//     document.querySelectorAll('.highlight pre code').forEach(codeBlock => {
//         const previousSibling = codeBlock.previousElementSibling;
//         const toggleButton = document.createElement('button');
//         toggleButton.textContent = 'Toggle Wrap';
//         toggleButton.className = 'code-wrap-toggle';

//         toggleButton.addEventListener('click', () => {
//             codeBlock.classList.toggle('codewrap');
//         });

//         // Insert button at the top of the code block
//         //codeBlock.insertBefore(toggleButton, codeBlock.firstChild);
//         previousSibling.appendChild(toggleButton)
//     });
// });