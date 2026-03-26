// Prevent dark mode flash by applying theme before React loads
// This script runs early to avoid FOUC (Flash of Unstyled Content)
(function() {
  if (localStorage.getItem('runic_theme') === 'dark' ||
      (!localStorage.getItem('runic_theme') && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
    document.documentElement.classList.add('dark')
  }
})()
