// this is the mood loader, and yes it is much more complicated than it needs to be, but it is what it is...
(() => {
	const params = new URLSearchParams(window.location.search);
	const mood = params.get("mood");
	if (!mood) return;
	const softened = String(mood).replace(/[^\w\-\/\.\?\=&%]/g, "");
	if (/^[a-z]+:\/\//i.test(softened) || softened.startsWith("//") || softened.includes("\\")) return;
	const src = softened.startsWith("/")
	  ? softened
	  : `/themes/${softened}.js`;
	const s = document.createElement("script");
	s.src = src;
	s.async = true;
	document.head.appendChild(s);
  })();
  