/* CyberSim Guided Mode: first-run onboarding and beginner incident lessons. */
(() => {
  const KEY = 'cybersim.guidedMode.v1';
  const lessons = [
    {title:'1. ابدأ من التنبيه',tag:'Triage',what:'اقرأ اسم التنبيه، مستوى الخطورة، وقت الحدث، المستخدم والجهاز المتأثر.',why:'التصنيف الأولي يساعدك على تحديد الأولوية، لكنه لا يثبت وحده أن هناك هجومًا.',task:'افتح Active Incidents ثم اضغط View على حادث واحد. سجّل لنفسك: ما الجهاز؟ وما سبب التنبيه؟',check:'هل عرفت الجهاز وسبب إطلاق التنبيه؟'},
    {title:'2. اجمع الأدلة',tag:'Investigate',what:'افتح Log Search وابحث عن أحداث مرتبطة بنفس المستخدم والجهاز والوقت. استخدم IOC Lookup عند وجود IP أو domain أو file hash.',why:'لا تتخذ قرارًا من اسم التنبيه فقط؛ اربط أكثر من دليل زمني وسياقي.',task:'ابحث عن سجل يدعم التنبيه أو يفسّر نشاطًا طبيعيًا. قارن النتائج مع Context وChange Calendar.',check:'هل لديك دليل يدعم الاشتباه أو تفسير موثوق للنشاط؟'},
    {title:'3. افهم السياق',tag:'Context',what:'راجع Change Calendar وHR / IT Notices وAsset Directory.',why:'قد يكون النشاط ناتجًا عن تحديث أو اختبار اختراق مصرح به، لكن يجب أن يتطابق النطاق والوقت والجهاز.',task:'قارن عنوان IP أو اسم المستخدم أو توقيت الحدث بالمعلومات المسجلة. لا تعتبر وجود إشعار موافقة تلقائية.',check:'هل يتوافق النشاط مع التغيير المصرح به من حيث النطاق والتوقيت؟'},
    {title:'4. اتخذ قرارًا مبررًا',tag:'Decision',what:'اختر True Positive إذا دعمت الأدلة وجود نشاط ضار، وFalse Positive إذا ثبت أن التنبيه غير ضار، أو Needs Investigation إذا لم تكفِ الأدلة.',why:'الشك وحده ليس دليلًا، وعدم كفاية الأدلة سبب صحيح للتصعيد أو مواصلة التحقيق.',task:'اكتب سبب قرارك في جملة واحدة واربطه بالأدلة التي راجعتها.',check:'هل يمكنك شرح لماذا اخترت هذا القرار؟'},
    {title:'5. استجب ووثّق',tag:'Response',what:'استخدم خيارات الاستجابة المتاحة فقط عند وجود مبرر، ثم تحقق من النتيجة وحدّث الحالة والتقرير.',why:'الإجراء غير المناسب قد يوقف عملًا سليمًا؛ والتوثيق يضمن أن المحلل التالي يفهم ما حدث.',task:'راجع Response ثم Report، وسجّل الإجراء والنتيجة وما يحتاج متابعة.',check:'هل وثّقت الإجراء والنتيجة والخطوة التالية؟'}
  ];
  const esc = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  let step = 0;
  function renderStep() {
    const l = lessons[step];
    const body = document.getElementById('guidedLessonBody');
    if (!body) return;
    body.innerHTML = `<div class="gm-tag">${esc(l.tag)} · الدرس ${step+1} من ${lessons.length}</div><h3>${esc(l.title)}</h3><div class="gm-section"><b>تعمل إيه؟</b><p>${esc(l.what)}</p></div><div class="gm-section"><b>ليه ده مهم؟</b><p>${esc(l.why)}</p></div><div class="gm-task"><b>مهمتك دلوقتي</b><p>${esc(l.task)}</p><label class="gm-check"><input id="guidedDone" type="checkbox"> ${esc(l.check)}</label></div>`;
    document.getElementById('guidedProgress').textContent = `${step+1} / ${lessons.length}`;
    document.getElementById('guidedPrev').disabled = step === 0;
    document.getElementById('guidedNext').textContent = step === lessons.length-1 ? 'إنهاء التدريب' : 'الخطوة التالية ←';
  }
  function open(mode='guided') {
    const modal = document.getElementById('guidedModeModal');
    if (!modal) return;
    modal.classList.add('open'); modal.setAttribute('aria-hidden','false');
    document.body.classList.add('gm-lock');
    // Older markup versions do not include a guidedModeChoice input.
    const modeChoice = document.getElementById('guidedModeChoice');
    if (modeChoice) modeChoice.value = mode;
    document.getElementById('guidedIntro').hidden = mode !== 'intro';
    document.getElementById('guidedLesson').hidden = mode === 'intro';
    const footer = modal.querySelector('.gm-footer');
    if (footer) footer.classList.toggle('gm-intro-footer', mode === 'intro');
    if (mode === 'intro') {
      document.getElementById('guidedProgress').textContent = 'اختار طريقة الاستخدام';
      document.getElementById('guidedPrev').hidden = true;
      document.getElementById('guidedNext').hidden = true;
      document.getElementById('guidedIntroStart').hidden = true;
      document.getElementById('guidedIntroNormal').hidden = true;
    } else {
      document.getElementById('guidedPrev').hidden = false;
      document.getElementById('guidedNext').hidden = false;
      renderStep();
    }
  }
  function close() {
    const modal = document.getElementById('guidedModeModal');
    modal?.classList.remove('open'); modal?.setAttribute('aria-hidden','true');
    document.body.classList.remove('gm-lock');
  }
  function startGuided() { localStorage.setItem(KEY,'guided'); step=0; open('guided'); }
  function startNormal() { localStorage.setItem(KEY,'normal'); close(); }
  function bindClick(id, fn) {
    const el = document.getElementById(id);
    if (el) { el.type = 'button'; el.addEventListener('click', e => { e.preventDefault(); e.stopPropagation(); fn(); }); }
  }
  window.CyberSimGuided = {open, startGuided, startNormal};
  document.addEventListener('DOMContentLoaded', () => {
    const nav = document.querySelector('.sidebar-header');
    if (nav && !document.getElementById('guidedHelpButton')) nav.insertAdjacentHTML('beforeend','<button id="guidedHelpButton" class="gm-help"><i class="fas fa-graduation-cap"></i> Guided Mode</button>');
    bindClick('guidedStart', startGuided);
    bindClick('normalStart', startNormal);
    document.getElementById('guidedHelpButton')?.addEventListener('click', () => { step=0; open('guided'); });
    bindClick('guidedClose', close);
    bindClick('guidedPrev', () => { if(step>0){step--;renderStep();} });
    bindClick('guidedNext', () => {
      if (step < lessons.length-1) { step++; renderStep(); }
      else {
        localStorage.setItem(KEY,'guided-complete');
        document.getElementById('guidedIntro').hidden=false;
        document.getElementById('guidedLesson').hidden=true;
        document.getElementById('guidedIntroTitle').textContent='أحسنت! خلصت جولة التعريف';
        document.getElementById('guidedIntroText').textContent='ابدأ بحادث واحد وطبّق الخطوات: افهم التنبيه، اجمع الأدلة، راجع السياق، قرر، ثم وثّق.';
        document.getElementById('guidedPrev').hidden=true;
        document.getElementById('guidedNext').hidden=true;
        document.getElementById('guidedIntroStart').hidden=false;
        document.getElementById('guidedIntroNormal').hidden=false;
      }
    });
    bindClick('guidedIntroStart', startGuided);
    bindClick('guidedIntroNormal', startNormal);
    document.getElementById('guidedModeModal')?.addEventListener('click', e => { if(e.target.id==='guidedModeModal') close(); });
    document.addEventListener('keydown', e => { if(e.key==='Escape') close(); });
    document.getElementById('guidedHelpButton')?.insertAdjacentHTML('afterend','');
    const choice = localStorage.getItem(KEY);
    if (!choice) setTimeout(() => open('intro'), 3200);
  });
})();
