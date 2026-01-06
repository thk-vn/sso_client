// Smooth scroll for navigation links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth',
                block: 'start'
            });
            // Update active nav link
            document.querySelectorAll('.nav-link').forEach(link => {
                link.classList.remove('active');
            });
            this.classList.add('active');
        }
    });
});

// Update active nav link on scroll
const sections = document.querySelectorAll('.section');
const navLinks = document.querySelectorAll('.nav-link');

window.addEventListener('scroll', () => {
    let current = '';
    sections.forEach(section => {
        const sectionTop = section.offsetTop;
        const sectionHeight = section.clientHeight;
        if (window.pageYOffset >= sectionTop - 200) {
            current = section.getAttribute('id');
        }
    });

    navLinks.forEach(link => {
        link.classList.remove('active');
        if (link.getAttribute('href') === `#${current}`) {
            link.classList.add('active');
        }
    });
});

// Mobile menu toggle
const createMobileMenu = () => {
    if (window.innerWidth <= 768) {
        const sidebar = document.querySelector('.sidebar');
        const menuButton = document.createElement('button');
        menuButton.className = 'mobile-menu-btn';
        menuButton.innerHTML = '☰';
        menuButton.style.cssText = `
            position: fixed;
            top: 1rem;
            left: 1rem;
            z-index: 1000;
            background: var(--primary-color);
            color: white;
            border: none;
            padding: 0.75rem 1rem;
            border-radius: 6px;
            font-size: 1.5rem;
            cursor: pointer;
            box-shadow: 0 2px 8px rgba(0,0,0,0.2);
        `;
        menuButton.addEventListener('click', () => {
            sidebar.classList.toggle('open');
        });
        document.body.appendChild(menuButton);
    }
};

window.addEventListener('resize', createMobileMenu);
createMobileMenu();

// Copy code button
document.querySelectorAll('pre code').forEach(codeBlock => {
    const pre = codeBlock.parentElement;
    if (!pre.querySelector('.copy-btn')) {
        const copyBtn = document.createElement('button');
        copyBtn.className = 'copy-btn';
        copyBtn.textContent = 'Copy';
        copyBtn.style.cssText = `
            position: absolute;
            top: 0.5rem;
            right: 0.5rem;
            background: rgba(255,255,255,0.2);
            color: white;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.875rem;
        `;
        pre.style.position = 'relative';
        copyBtn.addEventListener('click', () => {
            navigator.clipboard.writeText(codeBlock.textContent).then(() => {
                copyBtn.textContent = 'Copied!';
                setTimeout(() => {
                    copyBtn.textContent = 'Copy';
                }, 2000);
            });
        });
        pre.appendChild(copyBtn);
    }
});

// Search functionality (optional)
const addSearch = () => {
    const searchInput = document.createElement('input');
    searchInput.type = 'text';
    searchInput.placeholder = 'Search documentation...';
    searchInput.className = 'search-input';
    searchInput.style.cssText = `
        width: 100%;
        padding: 0.75rem;
        border: 1px solid var(--border-color);
        border-radius: 6px;
        font-size: 0.9rem;
    `;
    
    const sidebarHeader = document.querySelector('.sidebar-header');
    sidebarHeader.appendChild(searchInput);
    
    searchInput.addEventListener('input', (e) => {
        const searchTerm = e.target.value.toLowerCase();
        navLinks.forEach(link => {
            const text = link.textContent.toLowerCase();
            const li = link.parentElement;
            if (text.includes(searchTerm)) {
                li.style.display = 'block';
            } else {
                li.style.display = searchTerm ? 'none' : 'block';
            }
        });
    });
};

addSearch();

