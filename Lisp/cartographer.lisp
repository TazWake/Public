;;;; cartographer.lisp
;;;; Kernel Symbol Cartographer — CLI, JSON, Baseline Diff, Heuristics

(defpackage :kernel-cartographer
  (:use :cl)
  (:export
   :main))

(in-package :kernel-cartographer)

;;;; ------------------------------------------------------------
;;;; Utilities
;;;; ------------------------------------------------------------

(defun split-spaces (line)
  "Split LINE on spaces without external libraries."
  (let ((parts '())
        (current ""))
    (loop for ch across line do
      (cond
        ((char= ch #\Space)
         (when (> (length current) 0)
           (push current parts)
           (setf current "")))
        (t (setf current (concatenate 'string current (string ch))))))
    (when (> (length current) 0)
      (push current parts))
    (nreverse parts)))

(defun parse-hex-address (s)
  (parse-integer s :radix 16))

;;;; ------------------------------------------------------------
;;;; Data Model
;;;; ------------------------------------------------------------

(defstruct ksym
  addr
  type
  name)

(defparameter *symbols* nil)
(defparameter *baseline-symbols* nil)

(defun parse-system-map-line (line)
  (let* ((parts (split-spaces line)))
    (when (>= (length parts) 3)
      (handler-case
          (make-ksym
           :addr (parse-hex-address (first parts))
           :type (second parts)
           :name (third parts))
        (error () nil)))))

(defun load-system-map (path)
  (let ((result '()))
    (with-open-file (in path :direction :input)
      (loop for line = (read-line in nil nil)
            while line
            for sym = (parse-system-map-line line)
            when sym do (push sym result)))
    (nreverse result)))

;;;; ------------------------------------------------------------
;;;; Classification Helpers
;;;; ------------------------------------------------------------

(defun symbol-executable-p (s)
  (member (ksym-type s) '("T" "t") :test #'string=))

(defun symbol-writable-p (s)
  (member (ksym-type s) '("D" "d" "B" "b") :test #'string=))

(defun symbol-readonly-p (s)
  (member (ksym-type s) '("R" "r") :test #'string=))

;;;; ------------------------------------------------------------
;;;; Queries
;;;; ------------------------------------------------------------

(defun find-symbols-by-type (type symbols)
  (remove-if-not (lambda (s) (string= (ksym-type s) type)) symbols))

(defun find-symbols-by-name-substring (substr symbols)
  (remove-if-not (lambda (s) (search substr (ksym-name s))) symbols))

(defun symbols-in-address-range (start end symbols)
  (remove-if-not
   (lambda (s)
     (let ((a (ksym-addr s)))
       (and (>= a start) (<= a end))))
   symbols))

(defun writable-globals (symbols)
  (remove-if-not #'symbol-writable-p symbols))

(defun executable-code (symbols)
  (remove-if-not #'symbol-executable-p symbols))

;;;; ------------------------------------------------------------
;;;; Heuristics for Rootkit Detection
;;;; ------------------------------------------------------------

(defun shadowed-symbols (symbols)
  (let ((table (make-hash-table :test #'equal))
        result)
    (dolist (s symbols)
      (push s (gethash (ksym-name s) table)))
    (maphash
     (lambda (name syms)
       (when (> (length syms) 1)
         (push (cons name syms) result)))
     table)
    result))

(defun executable-outliers (symbols
                            &key
                              (min #xffffffff80000000)
                              (max #xffffffffff000000))
  (remove-if-not
   (lambda (s)
     (and (symbol-executable-p s)
          (let ((a (ksym-addr s)))
            (or (< a min) (> a max)))))
   symbols))

(defun writable-syscall-patterns (symbols)
  (remove-if-not
   (lambda (s)
     (and (symbol-writable-p s)
          (let ((n (ksym-name s)))
            (or (search "sys_" n)
                (search "__x64_sys_" n)
                (search "do_sys_" n)))))
   symbols))

(defun address-monotonicity-anomalies (symbols)
  (let ((prev 0)
        anomalies)
    (dolist (s symbols)
      (let ((a (ksym-addr s)))
        (when (< a prev)
          (push s anomalies))
        (setf prev a)))
    (nreverse anomalies)))

(defun writable-hooklike-symbols (symbols)
  (remove-if-not
   (lambda (s)
     (and (symbol-writable-p s)
          (let ((n (ksym-name s)))
            (or (search "_hook" n)
                (search "_handler" n)
                (search "_ops" n)
                (search "_table" n)))))
   symbols))

;;;; ------------------------------------------------------------
;;;; Baseline Comparison
;;;; ------------------------------------------------------------

(defun diff-symbols (baseline suspect)
  "Return symbols present in suspect but not in baseline."
  (let ((base-names (make-hash-table :test #'equal))
        result)
    (dolist (s baseline)
      (setf (gethash (ksym-name s) base-names) t))
    (dolist (s suspect)
      (unless (gethash (ksym-name s) base-names)
        (push s result)))
    (nreverse result)))

;;;; ------------------------------------------------------------
;;;; JSON Output
;;;; ------------------------------------------------------------

(defun json-escape (s)
  (substitute #\\ #\" (substitute #\\ #\\ s)))

(defun symbol-to-json (s)
  (format nil
          "{\"addr\":\"~X\",\"type\":\"~A\",\"name\":\"~A\"}"
          (ksym-addr s)
          (ksym-type s)
          (json-escape (ksym-name s))))

(defun symbols-to-json (symbols)
  (format nil "[~{~A~^,~}]" (mapcar #'symbol-to-json symbols)))

;;;; ------------------------------------------------------------
;;;; Summary Output
;;;; ------------------------------------------------------------

(defun count-by-type (symbols)
  (let ((table (make-hash-table :test #'equal)))
    (dolist (s symbols)
      (incf (gethash (ksym-type s) table 0)))
    (let (result)
      (maphash (lambda (k v) (push (cons k v) result)) table)
      (sort result #'string< :key #'car))))

(defun print-summary (symbols)
  (format t "~&[Kernel Symbol Summary]~%")
  (format t "Total symbols: ~D~%" (length symbols))
  (format t "By type:~%")
  (dolist (pair (count-by-type symbols))
    (format t "  ~A: ~D~%" (car pair) (cdr pair)))
  (format t "~%Writable globals: ~D~%"
          (length (writable-globals symbols)))
  (format t "Executable outliers: ~D~%"
          (length (executable-outliers symbols)))
  (format t "Shadowed symbols: ~D~%"
          (length (shadowed-symbols symbols)))
  (format t "Writable syscall-patterns: ~D~%"
          (length (writable-syscall-patterns symbols)))
  (format t "Address monotonicity anomalies: ~D~%"
          (length (address-monotonicity-anomalies symbols)))
  (format t "Writable hook-like symbols: ~D~%"
          (length (writable-hooklike-symbols symbols))))

;;;; ------------------------------------------------------------
;;;; CLI Wrapper
;;;; ------------------------------------------------------------

(defun main ()
  (let ((args (copy-list sb-ext:*posix-argv*))
        map-file baseline-file summary json compare)

    ;; Drop program name
    (pop args)

    ;; Parse flags
    (loop while args do
      (let ((a (pop args)))
        (cond
          ((string= a "--map") (setf map-file (pop args)))
          ((string= a "--baseline") (setf baseline-file (pop args)))
          ((string= a "--summary") (setf summary t))
          ((string= a "--json") (setf json t))
          ((string= a "--compare") (setf compare t))
          (t (format t "Unknown argument: ~A~%" a)))))

    ;; Load maps
    (when map-file
      (setf *symbols* (load-system-map map-file)))

    (when baseline-file
      (setf *baseline-symbols* (load-system-map baseline-file)))

    ;; Comparison mode
    (when compare
      (let ((diff (diff-symbols *baseline-symbols* *symbols*)))
        (format t "~&[Baseline Differences]~%")
        (dolist (s diff)
          (format t "~A (~A) @ ~X~%"
                  (ksym-name s)
                  (ksym-type s)
                  (ksym-addr s)))
        (return-from main)))

    ;; JSON mode
    (when json
      (format t "~A~%" (symbols-to-json *symbols*))
      (return-from main))

    ;; Summary mode
    (when summary
      (print-summary *symbols*)
      (return-from main))

    ;; Default
    (format t "Loaded ~D symbols.~%" (length *symbols*))
    (format t "Use --summary or --json for output.~%")))
