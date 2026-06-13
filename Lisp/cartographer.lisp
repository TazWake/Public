;;;; cartographer.lisp
;;;; Minimal Lisp-based System.map intelligence extractor

(defpackage :kernel-cartographer
  (:use :cl)
  (:export
   :*symbols*
   :load-system-map
   :find-symbols-by-type
   :find-symbols-by-name-substring
   :symbols-in-address-range
   :writable-globals
   :executable-code
   :suspicious-addresses
   :summary))

(in-package :kernel-cartographer)

;;;; -----------------------------
;;;; Data model
;;;; -----------------------------

(defstruct ksym
  addr        ; integer address
  type        ; string, e.g. "T"
  name)       ; string

(defparameter *symbols* nil
  "Global list of KSYM objects representing the loaded System.map.")

;;;; -----------------------------
;;;; Parsing helpers
;;;; -----------------------------

(defun parse-hex-address (s)
  "Parse a hex string S into an integer."
  (parse-integer s :radix 16))

(defun parse-system-map-line (line)
  "Parse a single System.map line into a KSYM or NIL if malformed.
Expected format: <addr> <type> <name>"
  (let* ((parts (remove "" (split-sequence:split-sequence #\Space line)))
         (len   (length parts)))
    (when (>= len 3)
      (let ((addr-str (nth 0 parts))
            (type-str (nth 1 parts))
            (name-str (nth 2 parts)))
        (handler-case
            (make-ksym :addr (parse-hex-address addr-str)
                       :type type-str
                       :name name-str)
          (error () nil))))))

;;;; -----------------------------
;;;; File loading
;;;; -----------------------------

(defun load-system-map (path)
  "Load System.map from PATH into *SYMBOLS*.
Returns the number of symbols loaded."
  (setf *symbols* nil)
  (with-open-file (in path :direction :input)
    (loop for line = (read-line in nil nil)
          while line
          for sym = (parse-system-map-line line)
          when sym do (push sym *symbols*)))
  (setf *symbols* (nreverse *symbols*))
  (length *symbols*))

;;;; -----------------------------
;;;; Classification helpers
;;;; -----------------------------

(defun symbol-executable-p (sym)
  (member (ksym-type sym) '("T" "t") :test #'string=))

(defun symbol-writable-p (sym)
  (member (ksym-type sym) '("D" "d" "B" "b") :test #'string=))

(defun symbol-readonly-p (sym)
  (member (ksym-type sym) '("R" "r") :test #'string=))

(defun symbol-weak-p (sym)
  (member (ksym-type sym) '("W" "w") :test #'string=))

(defun symbol-absolute-p (sym)
  (string= (ksym-type sym) "A"))

;;;; -----------------------------
;;;; Query functions
;;;; -----------------------------

(defun find-symbols-by-type (type &optional (symbols *symbols*))
  "Return all symbols whose TYPE matches (string=)."
  (remove-if-not (lambda (s) (string= (ksym-type s) type)) symbols))

(defun find-symbols-by-name-substring (substr &optional (symbols *symbols*))
  "Return all symbols whose name contains SUBSTR (case-sensitive)."
  (remove-if-not
   (lambda (s)
     (search substr (ksym-name s)))
   symbols))

(defun symbols-in-address-range (start end &optional (symbols *symbols*))
  "Return all symbols with addresses in [START, END]."
  (remove-if-not
   (lambda (s)
     (let ((a (ksym-addr s)))
       (and (>= a start) (<= a end))))
   symbols))

(defun writable-globals (&optional (symbols *symbols*))
  "Return all writable global symbols (D/d/B/b)."
  (remove-if-not #'symbol-writable-p symbols))

(defun executable-code (&optional (symbols *symbols*))
  "Return all executable code symbols (T/t)."
  (remove-if-not #'symbol-executable-p symbols))

;;;; -----------------------------
;;;; Simple anomaly heuristics
;;;; -----------------------------

(defun suspicious-addresses (&key (min #xffffffff80000000)
                                  (max #xffffffffffffffff)
                                  (symbols *symbols*))
  "Return symbols whose addresses fall outside an expected kernel range.
Defaults are rough x86_64 kernel virtual address bounds."
  (remove-if-not
   (lambda (s)
     (let ((a (ksym-addr s)))
       (or (< a min) (> a max))))
   symbols))

(defun count-by-type (&optional (symbols *symbols*))
  "Return an alist of (TYPE . COUNT) for SYMBOLS."
  (let ((table (make-hash-table :test #'equal)))
    (dolist (s symbols)
      (incf (gethash (ksym-type s) table 0)))
    (let (result)
      (maphash (lambda (k v) (push (cons k v) result)) table)
      (sort result #'string< :key #'car))))

;;;; -----------------------------
;;;; Summary / reporting
;;;; -----------------------------

(defun summary (&optional (symbols *symbols*))
  "Print a small forensic summary of the loaded System.map."
  (format t "~&[Kernel Symbol Cartographer Summary]~%")
  (format t "Total symbols: ~D~%" (length symbols))
  (format t "By type:~%")
  (dolist (pair (count-by-type symbols))
    (format t "  ~A: ~D~%" (car pair) (cdr pair)))
  (let* ((w (length (writable-globals symbols)))
         (x (length (executable-code symbols)))
         (sus (length (suspicious-addresses :symbols symbols))))
    (format t "~%Writable globals: ~D~%" w)
    (format t "Executable symbols: ~D~%" x)
    (format t "Suspicious addresses (out-of-range): ~D~%" sus))
  (values))

;;;; -----------------------------
;;;; Tiny convenience REPL helpers
;;;; -----------------------------

(defun demo (&optional (path #P"/boot/System.map"))
  "Quick demo: load PATH, print summary, and return *SYMBOLS*."
  (format t "~&Loading System.map from ~A ...~%" path)
  (let ((n (load-system-map path)))
    (format t "Loaded ~D symbols.~%~%" n)
    (summary)
    *symbols*))
