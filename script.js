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
    fontControl.textContent = isLarge ? '文字を標準に戻す' : '文字を大きくする';
  });
}

// トップページの新着情報：CMSで差し替わった後も再初期化できます。
const newsCarouselCleanup = new WeakMap();
window.initializeNewsCarousels = () => document.querySelectorAll('[data-news-carousel]').forEach((carousel) => {
  newsCarouselCleanup.get(carousel)?.();
  const track = carousel.querySelector('.news-track');
  const previous = carousel.querySelector('[data-news-prev]');
  const next = carousel.querySelector('[data-news-next]');
  if (!track || !previous || !next) return;
  const cards = Array.from(track.querySelectorAll('.news-card'));
  let currentIndex = 0;

  const visibleCards = () => (window.innerWidth <= 700 ? 1 : window.innerWidth <= 1100 ? 2 : 3);
  const render = () => {
    const maxIndex = Math.max(0, cards.length - visibleCards());
    currentIndex = Math.max(0, Math.min(currentIndex, maxIndex));
    const gap = Number.parseFloat(getComputedStyle(track).gap) || 0;
    const cardWidth = cards[0]?.getBoundingClientRect().width || 0;
    track.style.transform = `translateX(-${currentIndex * (cardWidth + gap)}px)`;
    previous.disabled = currentIndex === 0;
    next.disabled = currentIndex === maxIndex;
  };

  const onPrevious = () => { currentIndex -= 1; render(); };
  const onNext = () => { currentIndex += 1; render(); };
  previous.addEventListener('click', onPrevious);
  next.addEventListener('click', onNext);
  window.addEventListener('resize', render);
  newsCarouselCleanup.set(carousel, () => {
    previous.removeEventListener('click', onPrevious);
    next.removeEventListener('click', onNext);
    window.removeEventListener('resize', render);
  });
  render();
});
window.initializeNewsCarousels();
