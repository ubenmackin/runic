export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
    colors: {
      runic: {
        50: '#f0f4ff',
        100: '#dce6fd',
        500: '#4f6ef7',
        600: '#3b55e6',
        700: '#2e43c4',
        900: '#1a2566',
      },
      // Arcane Mystic Dark Theme Colors
      charcoal: {
        dark: 'rgb(24, 24, 24)',
        darkest: 'rgb(10, 10, 10)',
      },
      'purple-active': 'rgb(159, 79, 248)',
      'amber-primary': 'rgb(193, 158, 91)',
      'amber-muted': 'rgb(100, 80, 50)',
      'light-neutral': '#fafafa',
      'gold-highlight': 'rgb(219, 189, 126)',
            'gray-border': 'rgb(35, 35, 35)',
            },
      keyframes: {
        importWizardFadeIn: {
          from: { opacity: '0' },
          to: { opacity: '1' },
        },
        importWizardSlideUp: {
          from: { opacity: '0', transform: 'translateY(20px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
      },
      animation: {
        'import-wizard-fade-in': 'importWizardFadeIn 0.2s ease-out',
        'import-wizard-slide-up': 'importWizardSlideUp 0.3s ease-out',
      },
        }
    }
};
