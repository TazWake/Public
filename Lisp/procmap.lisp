;;;; procmap.lisp
;;;; Process Memory-Map Cartographer — parses /proc/<pid>/maps and triages a
;;;; process address space for code-injection and tampering indicators.

(defpackage :procmap
  (:use :cl)
  (:export
   :main))

(in-package :procmap)

;;;; ------------------------------------------------------------
;;;; Utilities
;;;; ------------------------------------------------------------

(defun whitespace-p (ch)
  (or (char= ch #\Space) (char= ch #\Tab)))

;; A /proc/<pid>/maps line is five whitespace-separated fields followed by an
;; optional pathname -- and that pathname can itself contain spaces (e.g. a
;; library installed under a path with a space, or the literal " (deleted)"
;; suffix). So we split off exactly the first five fields and keep the entire
;; remainder verbatim as the sixth element rather than naively splitting on
;; every space. Dependency-free, like cartographer's split-spaces.
(defun split-maps-fields (line)
  "Return (F1 F2 F3 F4 F5 PATHNAME) for LINE; PATHNAME is the untouched remainder."
  (let ((fields '())
        (i 0)
        (len (length line)))
    (flet ((skip-ws ()
             (loop while (and (< i len) (whitespace-p (char line i))) do (incf i))))
      (dotimes (n 5)
        (skip-ws)
        (let ((start i))
          (loop while (and (< i len) (not (whitespace-p (char line i)))) do (incf i))
          (push (subseq line start i) fields)))
      (skip-ws)
      (push (subseq line i) fields)        ; remainder = pathname (may be "")
      (nreverse fields))))

(defun parse-hex (s)
  (parse-integer s :radix 16))

(defun string-prefix-p (prefix s)
  (let ((lp (length prefix)))
    (and (>= (length s) lp)
         (string= prefix s :end2 lp))))

(defun string-suffix-p (suffix s)
  (let ((ls (length s))
        (lf (length suffix)))
    (and (>= ls lf)
         (string= suffix s :start2 (- ls lf)))))

;;;; ------------------------------------------------------------
;;;; Data Model
;;;; ------------------------------------------------------------

;; One mapped region of a process address space. A maps line looks like:
;;   7f3c8a400000-7f3c8a428000 r-xp 00000000 08:01 1234567  /usr/lib/libc.so.6
;; START/END/SIZE/OFFSET/INODE are integers; DEV is kept as the raw "maj:min"
;; string; PATH is NIL for anonymous mappings. KIND is a derived classification.
(defstruct vmregion
  start end size
  perm-r perm-w perm-x
  shared-p                      ; T = shared ('s'), NIL = private ('p')
  offset dev inode
  path
  kind)

;; Module-level state populated by MAIN (mirrors cartographer's globals so the
;; CLI dispatch and an interactive REPL workflow stay simple).
(defparameter *regions* nil)
(defparameter *baseline-regions* nil)

(defun shared-lib-name-p (path)
  ;; Matches both "libfoo.so" and versioned "libfoo.so.6.0".
  (or (string-suffix-p ".so" path)
      (search ".so." path)))

;; KIND is decided from the pathname alone (the inode is informational here).
;; Pseudo-paths are wrapped in [...]; a real path may carry a " (deleted)"
;; suffix the kernel appends when the backing file has been unlinked while
;; still mapped -- a common malware tactic (run, then delete the binary).
(defun classify-kind (path)
  (cond
    ((null path)                          :anon)
    ((string= path "[stack]")             :stack)
    ((string= path "[heap]")              :heap)
    ((string= path "[vdso]")              :vdso)
    ((string= path "[vvar]")              :vvar)
    ((string= path "[vsyscall]")          :vsyscall)
    ;; [anon:name] (Android/newer kernels) is still anonymous memory.
    ((char= (char path 0) #\[)            :anon)
    ((string-suffix-p " (deleted)" path)  :deleted-file)
    ((shared-lib-name-p path)             :shared-lib)
    (t                                    :file)))

(defun parse-maps-line (line)
  ;; HANDLER-CASE returns NIL on any malformed field so a single bad line never
  ;; aborts the whole load (same defensive posture as cartographer).
  (let ((f (split-maps-fields line)))
    (when (= (length f) 6)
      (handler-case
          (destructuring-bind (addr perms offset dev inode path) f
            (let* ((dash  (position #\- addr))
                   (start (parse-hex (subseq addr 0 dash)))
                   (end   (parse-hex (subseq addr (1+ dash))))
                   (path* (if (string= path "") nil path)))
              (make-vmregion
               :start start
               :end end
               :size (- end start)
               :perm-r (char= (char perms 0) #\r)
               :perm-w (char= (char perms 1) #\w)
               :perm-x (char= (char perms 2) #\x)
               :shared-p (char= (char perms 3) #\s)
               :offset (parse-hex offset)
               :dev dev
               :inode (parse-integer inode)
               :path path*
               :kind (classify-kind path*))))
        (error () nil)))))

(defun load-maps-file (path)
  (let ((result '()))
    (with-open-file (in path :direction :input)
      (loop for line = (read-line in nil nil)
            while line
            for region = (parse-maps-line line)
            when region do (push region result)))
    (nreverse result)))

(defun load-maps-pid (pid)
  "Load the live maps of PID via /proc/<pid>/maps."
  (load-maps-file (format nil "/proc/~A/maps" pid)))

;;;; ------------------------------------------------------------
;;;; Formatting Helpers
;;;; ------------------------------------------------------------

(defun perms-string (r)
  "Reconstruct the rwxp/s permission string for region R."
  (format nil "~C~C~C~C"
          (if (vmregion-perm-r r) #\r #\-)
          (if (vmregion-perm-w r) #\w #\-)
          (if (vmregion-perm-x r) #\x #\-)
          (if (vmregion-shared-p r) #\s #\p)))

;;;; ------------------------------------------------------------
;;;; Heuristics for Code Injection / Tampering
;;;; ------------------------------------------------------------

;; 1. Executable anonymous memory: code running from a mapping with no backing
;;    file. The canonical signature of injected shellcode/loaders. NOTE: JIT
;;    engines (browsers, JVM, V8, LuaJIT...) legitimately produce the same
;;    signature, so expect benign hits on JIT-heavy processes.
(defun executable-anonymous (regions)
  (remove-if-not
   (lambda (r) (and (vmregion-perm-x r) (eq (vmregion-kind r) :anon)))
   regions))

;; 2. W+X regions: simultaneously writable and executable. Modern kernels and
;;    loaders enforce W^X, so a live W+X mapping is rare and worth inspecting
;;    (self-modifying code, naive JITs, or an attacker staging a payload).
(defun wx-regions (regions)
  (remove-if-not
   (lambda (r) (and (vmregion-perm-w r) (vmregion-perm-x r)))
   regions))

;; 3. Deleted-file mappings: the backing file was unlinked while still mapped.
;;    Executable ones are the strongest signal (running code from a binary that
;;    no longer exists on disk), but all are reported.
(defun deleted-file-mappings (regions)
  (remove-if-not
   (lambda (r) (eq (vmregion-kind r) :deleted-file))
   regions))

;; 4. Unexpected executable load paths. Legitimate code is mapped from a small
;;    set of system directories; an *executable* file-backed mapping from
;;    anywhere else (/tmp, /dev/shm, /home, hidden dirs, ...) is suspicious.
;;    The multiarch dirs (e.g. /usr/lib/x86_64-linux-gnu) fall under /usr/lib/.
(defparameter *standard-exec-dirs*
  '("/lib/" "/lib64/" "/usr/lib/" "/usr/lib64/" "/usr/local/lib/"
    "/bin/" "/sbin/" "/usr/bin/" "/usr/sbin/" "/usr/local/bin/" "/opt/"))

(defun standard-exec-path-p (path)
  (some (lambda (dir) (string-prefix-p dir path)) *standard-exec-dirs*))

(defun unexpected-library-paths (regions)
  (remove-if-not
   (lambda (r)
     (and (member (vmregion-kind r) '(:shared-lib :file))
          (vmregion-perm-x r)
          (vmregion-path r)
          (not (standard-exec-path-p (vmregion-path r)))))
   regions))

;; 5. Heap/stack anomalies. A process should have exactly one [heap] and one
;;    [stack] (thread stacks are anonymous on modern kernels, not labelled),
;;    and neither should ever be executable. Flag executable stack/heap and any
;;    duplicate [stack]/[heap] regions.
(defun stack-heap-anomalies (regions)
  (let ((stacks (remove-if-not (lambda (r) (eq (vmregion-kind r) :stack)) regions))
        (heaps  (remove-if-not (lambda (r) (eq (vmregion-kind r) :heap)) regions))
        (result '()))
    (dolist (r regions)
      (when (and (member (vmregion-kind r) '(:stack :heap))
                 (vmregion-perm-x r))
        (pushnew r result)))
    (when (> (length stacks) 1) (dolist (r stacks) (pushnew r result)))
    (when (> (length heaps) 1)  (dolist (r heaps)  (pushnew r result)))
    (nreverse result)))

;; 6. Non-canonical region ordering. The kernel emits maps sorted ascending by
;;    start address; a region whose start is below its predecessor means the
;;    capture was reordered/forged. Relies on REGIONS being in original file
;;    order (LOAD-MAPS-* preserves it) -- direct analogue of cartographer's
;;    address-monotonicity-anomalies.
(defun region-ordering-anomalies (regions)
  (let ((prev 0)
        result)
    (dolist (r regions)
      (let ((start (vmregion-start r)))
        (when (< start prev)
          (push r result))
        (setf prev start)))
    (nreverse result)))

;;;; ------------------------------------------------------------
;;;; Baseline Comparison
;;;; ------------------------------------------------------------

;; Two ways to key a region for diffing, selected by --compare-by:
;;  - path:    (pathname + perms) signature, stable across ASLR re-randomisation;
;;             best for comparing a process against a known-good profile.
;;  - address: raw start-end range; exact, but only meaningful between snapshots
;;             of the *same* running process (ASLR moves everything otherwise).
(defun region-path-key (r)
  (format nil "~A|~A" (or (vmregion-path r) "") (perms-string r)))

(defun region-addr-key (r)
  (format nil "~X-~X" (vmregion-start r) (vmregion-end r)))

(defun diff-regions (baseline suspect key-fn)
  "Return regions in SUSPECT whose KEY-FN value is absent from BASELINE."
  (let ((seen (make-hash-table :test #'equal))
        result)
    (dolist (r baseline)
      (setf (gethash (funcall key-fn r) seen) t))
    (dolist (r suspect)
      (unless (gethash (funcall key-fn r) seen)
        (push r result)))
    (nreverse result)))

;;;; ------------------------------------------------------------
;;;; JSON Output
;;;; ------------------------------------------------------------

;; LIMITATION (shared with cartographer): SUBSTITUTE is char-for-char and cannot
;; expand " into \". Safe here because mapping paths in /proc are filesystem
;; paths that effectively never contain " or \. Replace with a real escaper if
;; this is ever pointed at untrusted input.
(defun json-escape (s)
  (substitute #\\ #\" (substitute #\\ #\\ s)))

(defun region-to-json (r)
  (format nil
          "{\"start\":\"~X\",\"end\":\"~X\",\"size\":~D,\"perms\":\"~A\",\"kind\":\"~A\",\"path\":~A}"
          (vmregion-start r)
          (vmregion-end r)
          (vmregion-size r)
          (perms-string r)
          (string-downcase (symbol-name (vmregion-kind r)))
          (if (vmregion-path r)
              (format nil "\"~A\"" (json-escape (vmregion-path r)))
              "null")))

(defun regions-to-json (regions)
  (format nil "[~{~A~^,~}]" (mapcar #'region-to-json regions)))

;;;; ------------------------------------------------------------
;;;; Summary Output
;;;; ------------------------------------------------------------

(defun count-by (key-fn regions)
  "Return a sorted alist of (KEY . COUNT) over REGIONS, keyed by KEY-FN."
  (let ((table (make-hash-table :test #'equal)))
    (dolist (r regions)
      (incf (gethash (funcall key-fn r) table 0)))
    (let (result)
      (maphash (lambda (k v) (push (cons k v) result)) table)
      (sort result #'string< :key (lambda (p) (princ-to-string (car p)))))))

(defun print-summary (regions)
  (format t "~&[Process Memory-Map Summary]~%")
  (format t "Total regions: ~D~%" (length regions))
  (format t "By kind:~%")
  (dolist (pair (count-by (lambda (r) (vmregion-kind r)) regions))
    (format t "  ~A: ~D~%" (string-downcase (princ-to-string (car pair))) (cdr pair)))
  (format t "By permissions:~%")
  (dolist (pair (count-by #'perms-string regions))
    (format t "  ~A: ~D~%" (car pair) (cdr pair)))
  (format t "~%Executable anonymous regions: ~D~%"
          (length (executable-anonymous regions)))
  (format t "W+X regions: ~D~%"
          (length (wx-regions regions)))
  (format t "Deleted-file mappings: ~D~%"
          (length (deleted-file-mappings regions)))
  (format t "Unexpected executable paths: ~D~%"
          (length (unexpected-library-paths regions)))
  (format t "Heap/stack anomalies: ~D~%"
          (length (stack-heap-anomalies regions)))
  (format t "Region ordering anomalies: ~D~%"
          (length (region-ordering-anomalies regions))))

;;;; ------------------------------------------------------------
;;;; CLI Wrapper
;;;; ------------------------------------------------------------

;; CLI entry point (exported; used as the :toplevel of a saved executable, or
;; called directly under `sbcl --load`). Output modes are mutually exclusive and
;; checked in priority order -- compare > json > summary > default -- each
;; returning early, so passing several flags uses the first match.
(defun main ()
  (let ((args (copy-list sb-ext:*posix-argv*))
        pid map-file baseline-file summary json compare
        (compare-by "path"))

    ;; *posix-argv* starts with the program name (or "sbcl"); discard it.
    (pop args)

    ;; Parse flags
    (loop while args do
      (let ((a (pop args)))
        (cond
          ((string= a "--pid")        (setf pid (pop args)))
          ((string= a "--maps")       (setf map-file (pop args)))
          ((string= a "--baseline")   (setf baseline-file (pop args)))
          ((string= a "--summary")    (setf summary t))
          ((string= a "--json")       (setf json t))
          ((string= a "--compare")    (setf compare t))
          ((string= a "--compare-by") (setf compare-by (pop args)))
          (t (format t "Unknown argument: ~A~%" a)))))

    ;; Load primary map: an explicit --maps file wins over --pid.
    (cond
      (map-file (setf *regions* (load-maps-file map-file)))
      (pid      (setf *regions* (load-maps-pid pid))))

    (when baseline-file
      (setf *baseline-regions* (load-maps-file baseline-file)))

    ;; Comparison mode
    (when compare
      (let* ((key-fn (cond
                       ((string= compare-by "address") #'region-addr-key)
                       ((string= compare-by "path")    #'region-path-key)
                       (t (format t "Unknown --compare-by '~A'; using 'path'.~%"
                                  compare-by)
                          #'region-path-key)))
             (diff (diff-regions *baseline-regions* *regions* key-fn)))
        (format t "~&[Baseline Differences] (by ~A)~%" compare-by)
        (dolist (r diff)
          (format t "~X-~X ~A ~A~%"
                  (vmregion-start r)
                  (vmregion-end r)
                  (perms-string r)
                  (or (vmregion-path r) "[anonymous]")))
        (return-from main)))

    ;; JSON mode
    (when json
      (format t "~A~%" (regions-to-json *regions*))
      (return-from main))

    ;; Summary mode
    (when summary
      (print-summary *regions*)
      (return-from main))

    ;; Default
    (format t "Loaded ~D regions.~%" (length *regions*))
    (format t "Use --summary or --json for output (provide --pid or --maps).~%")))
