// Shared body scroll lock. Dialogs can stack (for example a confirm Modal
// opened on top of a Sheet) and close in any order, so the original
// overflow value is saved by the first lock and restored only when the
// last lock is released.
let lockCount = 0;
let savedOverflow = "";

export function lockBodyScroll(): () => void {
  if (lockCount === 0) {
    savedOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
  }
  lockCount += 1;
  let released = false;
  return () => {
    if (released) return;
    released = true;
    lockCount -= 1;
    if (lockCount === 0) document.body.style.overflow = savedOverflow;
  };
}
