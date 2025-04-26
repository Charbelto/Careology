// JavaScript for handling the Messages Modal
document.getElementById('inboxBtn')?.addEventListener('click', function () {
    const inboxModal = document.getElementById('inboxModal');
    inboxModal.style.display = 'block';

    // Simulate loading messages dynamically
    const messageList = document.getElementById('messageList');
    messageList.innerHTML = '<p>Loading messages...</p>';

    // Example: Fetch messages from the server (replace with actual API call)
    setTimeout(() => {
        messageList.innerHTML = `
            <div class="message-item">Message 1: Hello!</div>
            <div class="message-item">Message 2: How are you?</div>
        `;
    }, 1000);
});

// Close the inbox modal
document.querySelector('#inboxModal .close-modal')?.addEventListener('click', function () {
    document.getElementById('inboxModal').style.display = 'none';
});

// Main functionality
document.addEventListener('DOMContentLoaded', function() {
    // Debug logging
    console.log('Script loaded');

    // Search Elements
    const searchInput = document.getElementById('searchInput');
    const searchBtn = document.querySelector('.search-btn');
    console.log('Search elements:', { searchInput, searchBtn });

    // Filter Elements
    const filterBtn = document.querySelector('.filter-btn');
    const filterDropdown = document.querySelector('.filter-dropdown');
    const minPriceInput = document.getElementById('minPrice');
    const maxPriceInput = document.getElementById('maxPrice');
    const minYearSelect = document.getElementById('minYear');
    const maxYearSelect = document.getElementById('maxYear');
    const brandSearch = document.getElementById('brandSearch');
    const locationSearch = document.getElementById('locationSearch');
    const clearFiltersBtn = document.querySelector('.clear-filters');
    const applyFiltersBtn = document.querySelector('.apply-filters');

    console.log('Filter elements:', {
        filterBtn,
        filterDropdown,
        minPriceInput,
        maxPriceInput,
        minYearSelect,
        maxYearSelect,
        brandSearch,
        locationSearch,
        clearFiltersBtn,
        applyFiltersBtn
    });

    // Search functionality
    function handleSearch(e) {
        e?.preventDefault();
        console.log('Search triggered');
        
        const searchTerm = searchInput?.value.trim();
        console.log('Search term:', searchTerm);
        
        if (searchTerm) {
            const currentUrl = new URL(window.location.href);
            currentUrl.searchParams.set('search', searchTerm);
            console.log('Redirecting to:', currentUrl.toString());
            window.location.href = currentUrl.toString();
        }
    }

    searchBtn?.addEventListener('click', handleSearch);
    
    searchInput?.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            handleSearch(e);
        }
    });

    // Filter dropdown toggle
    filterBtn?.addEventListener('click', function(e) {
        e.stopPropagation();
        console.log('Filter button clicked');
        filterDropdown?.classList.toggle('show');
    });

    // Close dropdown when clicking outside
    document.addEventListener('click', function(e) {
        if (filterDropdown?.classList.contains('show') && 
            !filterDropdown.contains(e.target) && 
            !filterBtn?.contains(e.target)) {
            console.log('Closing filter dropdown');
            filterDropdown.classList.remove('show');
        }
    });

    // Price inputs validation
    [minPriceInput, maxPriceInput].forEach(input => {
        input?.addEventListener('input', function() {
            this.value = this.value.replace(/[^0-9]/g, '');
            console.log(`${this.id} value:`, this.value);
        });
    });

    // Brand search filter
    brandSearch?.addEventListener('input', function() {
        const searchTerm = this.value.toLowerCase();
        console.log('Brand search term:', searchTerm);
        
        document.querySelectorAll('.brand-item').forEach(item => {
            const label = item.querySelector('span')?.textContent.toLowerCase() || '';
            const shouldShow = label.includes(searchTerm);
            item.style.display = shouldShow ? 'flex' : 'none';
            console.log('Brand item:', { label, shouldShow });
        });
    });

    // Location search filter
    locationSearch?.addEventListener('input', function() {
        const searchTerm = this.value.toLowerCase();
        console.log('Location search term:', searchTerm);
        
        document.querySelectorAll('.location-item').forEach(item => {
            const label = item.querySelector('span')?.textContent.toLowerCase() || '';
            const shouldShow = label.includes(searchTerm);
            item.style.display = shouldShow ? 'flex' : 'none';
            console.log('Location item:', { label, shouldShow });
        });
    });

    // Clear filters
    clearFiltersBtn?.addEventListener('click', function() {
        console.log('Clearing filters');
        
        // Reset all inputs
        if (searchInput) searchInput.value = '';
        if (minPriceInput) minPriceInput.value = '';
        if (maxPriceInput) maxPriceInput.value = '';
        if (minYearSelect) minYearSelect.value = '';
        if (maxYearSelect) maxYearSelect.value = '';
        if (brandSearch) brandSearch.value = '';
        if (locationSearch) locationSearch.value = '';

        // Reset all checkboxes
        document.querySelectorAll('input[type="checkbox"]').forEach(checkbox => {
            checkbox.checked = false;
        });

        // Show all items
        document.querySelectorAll('.brand-item, .location-item').forEach(item => {
            item.style.display = 'flex';
        });

        // Redirect to clear URL
        window.location.href = window.location.pathname;
    });

    // Apply filters
    applyFiltersBtn?.addEventListener('click', function() {
        console.log('Applying filters');
        
        const currentUrl = new URL(window.location.href);
        const params = currentUrl.searchParams;

        // Add search term if exists
        const searchTerm = searchInput?.value.trim();
        if (searchTerm) {
            params.set('search', searchTerm);
            console.log('Search term:', searchTerm);
        } else {
            params.delete('search');
        }

        // Add price range
        if (minPriceInput?.value) {
            params.set('min_price', minPriceInput.value);
            console.log('Min price:', minPriceInput.value);
        } else {
            params.delete('min_price');
        }

        if (maxPriceInput?.value) {
            params.set('max_price', maxPriceInput.value);
            console.log('Max price:', maxPriceInput.value);
        } else {
            params.delete('max_price');
        }

        // Add year range
        if (minYearSelect?.value) {
            params.set('min_year', minYearSelect.value);
            console.log('Min year:', minYearSelect.value);
        } else {
            params.delete('min_year');
        }

        if (maxYearSelect?.value) {
            params.set('max_year', maxYearSelect.value);
            console.log('Max year:', maxYearSelect.value);
        } else {
            params.delete('max_year');
        }

        // Add selected brands
        const selectedBrands = Array.from(document.querySelectorAll('.brand-item input[type="checkbox"]:checked'))
            .map(cb => cb.value);
        if (selectedBrands.length) {
            params.set('brands', selectedBrands.join(','));
            console.log('Selected brands:', selectedBrands);
        } else {
            params.delete('brands');
        }

        // Add selected locations
        const selectedLocations = Array.from(document.querySelectorAll('.location-item input[type="checkbox"]:checked'))
            .map(cb => cb.value);
        if (selectedLocations.length) {
            params.set('locations', selectedLocations.join(','));
            console.log('Selected locations:', selectedLocations);
        } else {
            params.delete('locations');
        }

        // Add selected colors
        const selectedColors = Array.from(document.querySelectorAll('.color-item input[type="checkbox"]:checked'))
            .map(cb => cb.value);
        if (selectedColors.length) {
            params.set('colors', selectedColors.join(','));
            console.log('Selected colors:', selectedColors);
        } else {
            params.delete('colors');
        }

        // Show loading state
        document.body.style.cursor = 'wait';

        // Redirect with filters
        const newUrl = currentUrl.toString();
        console.log('Redirecting to:', newUrl);
        window.location.href = newUrl;
    });
});

// Theme Toggle Functionality
document.addEventListener('DOMContentLoaded', () => {
    const themeToggle = document.querySelector('.theme-toggle');
    const mobileMenuToggle = document.querySelector('.mobile-menu-toggle');
    const mainNav = document.querySelector('.main-nav');
    
    // Theme Toggle
    const getCurrentTheme = () => localStorage.getItem('theme') || 'light';
    const setTheme = (theme) => {
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem('theme', theme);
        
        const icon = themeToggle?.querySelector('i');
        if (icon) {
            icon.className = theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
        }
        themeToggle?.setAttribute('aria-label', `Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`);
    };
    
    setTheme(getCurrentTheme());
    
    themeToggle?.addEventListener('click', () => {
        const currentTheme = getCurrentTheme();
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        setTheme(newTheme);
    });
    
    // Mobile Menu Toggle
    const toggleMobileMenu = (show) => {
        mainNav?.classList.toggle('active', show);
        const icon = mobileMenuToggle?.querySelector('i');
        if (icon) {
            icon.className = show ? 'fas fa-times' : 'fas fa-bars';
        }
        mobileMenuToggle?.setAttribute('aria-expanded', show);
    };
    
    mobileMenuToggle?.addEventListener('click', () => {
        const isExpanded = mobileMenuToggle.getAttribute('aria-expanded') === 'true';
        toggleMobileMenu(!isExpanded);
    });
    
    document.addEventListener('click', (event) => {
        const isClickInsideNav = mainNav?.contains(event.target);
        const isClickOnToggle = mobileMenuToggle?.contains(event.target);
        
        if (!isClickInsideNav && !isClickOnToggle && mainNav?.classList.contains('active')) {
            toggleMobileMenu(false);
        }
    });
    
    window.addEventListener('resize', () => {
        if (window.innerWidth > 768 && mainNav?.classList.contains('active')) {
            toggleMobileMenu(false);
        }
    });
});

// User Menu Dropdown
document.addEventListener('DOMContentLoaded', function() {
    const userButton = document.querySelector('.user-button');
    const userMenuDropdown = document.getElementById('userMenuDropdown');

    if (userButton && userMenuDropdown) {
        userButton.addEventListener('click', function(e) {
            e.stopPropagation();
            userMenuDropdown.classList.toggle('show');
        });

        document.addEventListener('click', function(e) {
            if (!userMenuDropdown.contains(e.target) && !userButton.contains(e.target)) {
                userMenuDropdown.classList.remove('show');
            }
        });

        userMenuDropdown.addEventListener('click', function(e) {
            e.stopPropagation();
        });
    }
});