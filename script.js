const menuButton = document.querySelector('.menu-button');
const nav = document.querySelector('.site-nav, .nav');

if (menuButton && nav) {
  menuButton.addEventListener('click', () => {
    const isOpen = nav.classList.toggle('open');
    menuButton.setAttribute('aria-expanded', String(isOpen));
  });

  nav.querySelectorAll('a').forEach((link) => {
    link.addEventListener('click', () => {
      nav.classList.remove('open');
      menuButton.setAttribute('aria-expanded', 'false');
    });
  });
}

const fontControl = document.querySelector('.font-control');

if (fontControl) {
  fontControl.addEventListener('click', () => {
    const isLarge = document.body.classList.toggle('large-text');
    fontControl.setAttribute('aria-pressed', String(isLarge));
    fontControl.textContent = isLarge ? '文字を標準に戻す' : '文字を大きく';
  });
}
