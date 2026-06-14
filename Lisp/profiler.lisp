;;;; profiler.lisp
;;;; ELF Section Forensic Profiler — 64-bit, little-endian ELF

(defpackage :elf-profiler
  (:use :cl)
  (:export :main))

(in-package :elf-profiler)

;;;; ------------------------------------------------------------
;;;; Low-level binary helpers (little-endian)
;;;; ------------------------------------------------------------

(defun read-u8 (in)
  (read-byte in nil nil))

(defun read-u16 (in)
  (let ((b0 (read-byte in nil nil))
        (b1 (read-byte in nil nil)))
    (when (and b0 b1)
      (+ b0 (ash b1 8)))))

(defun read-u32 (in)
  (let ((b0 (read-byte in nil nil))
        (b1 (read-byte in nil nil))
        (b2 (read-byte in nil nil))
        (b3 (read-byte in nil nil)))
    (when (and b0 b1 b2 b3)
      (+ b0
         (ash b1 8)
         (ash b2 16)
         (ash b3 24))))

(defun read-u64 (in)
  (let ((b0 (read-byte in nil nil))
        (b1 (read-byte in nil nil))
        (b2 (read-byte in nil nil))
        (b3 (read-byte in nil nil))
        (b4 (read-byte in nil nil))
        (b5 (read-byte in nil nil))
        (b6 (read-byte in nil nil))
        (b7 (read-byte in nil nil)))
    (when (and b0 b1 b2 b3 b4 b5 b6 b7)
      (+ b0
         (ash b1 8)
         (ash b2 16)
         (ash b3 24)
         (ash b4 32)
         (ash b5 40)
         (ash b6 48)
         (ash b7 56))))

(defun read-bytes (in n)
  (let ((vec (make-array n :element-type '(unsigned-byte 8))))
    (dotimes (i n vec)
      (let ((b (read-byte in nil nil)))
        (unless b
          (return vec))
        (setf (aref vec i) b)))))

(defun seek (in pos)
  (file-position in pos))

;;;; ------------------------------------------------------------
;;;; Data structures
;;;; ------------------------------------------------------------

(defstruct elf-header
  entry
  shoff
  shentsize
  shnum
  shstrndx)

(defstruct elf-section
  name
  type
  flags
  addr
  offset
  size
  link
  info
  addralign
  entsize
  bytes
  entropy)

(defparameter *sections* nil)

;;;; ------------------------------------------------------------
;;;; ELF header parsing (64-bit, little-endian)
;;;; ------------------------------------------------------------

(defun parse-elf-header (in)
  ;; e_ident
  (let ((magic (read-bytes in 4)))
    (unless (and (= (aref magic 0) #x7F)
                 (= (aref magic 1) (char-code #\E))
                 (= (aref magic 2) (char-code #\L))
                 (= (aref magic 3) (char-code #\F)))
      (error "Not an ELF file.")))
  (let ((class (read-u8 in))
        (data (read-u8 in)))
    (unless (= class 2)
      (error "Only 64-bit ELF supported."))
    (unless (= data 1)
      (error "Only little-endian ELF supported.")))
  ;; skip rest of e_ident
  (read-bytes in 10)
  ;; e_type, e_machine, e_version
  (read-u16 in)
  (read-u16 in)
  (read-u32 in)
  (let ((entry (read-u64 in))
        (phoff (read-u64 in))
        (shoff (read-u64 in))
        (flags (read-u32 in))
        (ehsize (read-u16 in))
        (phentsize (read-u16 in))
        (phnum (read-u16 in))
        (shentsize (read-u16 in))
        (shnum (read-u16 in))
        (shstrndx (read-u16 in)))
    (declare (ignore phoff flags ehsize phentsize phnum))
    (make-elf-header
     :entry entry
     :shoff shoff
     :shentsize shentsize
     :shnum shnum
     :shstrndx shstrndx)))

;;;; ------------------------------------------------------------
;;;; Section header parsing
;;;; ------------------------------------------------------------

(defun parse-section-header (in)
  (let ((name      (read-u32 in))
        (type      (read-u32 in))
        (flags     (read-u64 in))
        (addr      (read-u64 in))
        (offset    (read-u64 in))
        (size      (read-u64 in))
        (link      (read-u32 in))
        (info      (read-u32 in))
        (addralign (read-u64 in))
        (entsize   (read-u64 in)))
    (make-elf-section
     :name name
     :type type
     :flags flags
     :addr addr
     :offset offset
     :size size
     :link link
     :info info
     :addralign addralign
     :entsize entsize
     :bytes nil
     :entropy 0.0)))

(defun load-section-headers (in hdr)
  (let ((sections (make-array (elf-header-shnum hdr))))
    (seek in (elf-header-shoff hdr))
    (dotimes (i (elf-header-shnum hdr) sections)
      (setf (aref sections i) (parse-section-header in)))))

;;;; ------------------------------------------------------------
;;;; Section name resolution
;;;; ------------------------------------------------------------

(defun read-string-table (in sec)
  (seek in (elf-section-offset sec))
  (read-bytes in (elf-section-size sec)))

(defun resolve-section-names (in hdr sections)
  (let* ((strsec (aref sections (elf-header-shstrndx hdr)))
         (strtab (read-string-table in strsec)))
    (dotimes (i (length sections))
      (let* ((sec (aref sections i))
             (name-offset (elf-section-name sec)))
        (when (< name-offset (length strtab))
          (let ((name ""))
            (loop for idx from name-offset below (length strtab)
                  for ch = (aref strtab idx)
                  until (zerop ch) do
                    (setf name (concatenate 'string name (string (code-char ch)))))
            (setf (elf-section-name sec) name)))))
    sections))

;;;; ------------------------------------------------------------
;;;; Section content and entropy
;;;; ------------------------------------------------------------

(defun section-bytes (in sec)
  (seek in (elf-section-offset sec))
  (read-bytes in (elf-section-size sec)))

(defun compute-entropy (bytes)
  (let ((freq (make-array 256 :initial-element 0))
        (len (length bytes)))
    (when (zerop len)
      (return-from compute-entropy 0.0))
    (dotimes (i len)
      (incf (aref freq (aref bytes i))))
    (let ((entropy 0.0))
      (dotimes (i 256 entropy)
        (let ((p (/ (aref freq i) (float len))))
          (when (> p 0)
            (incf entropy (* p (log (/ 1 p) 2)))))))))

(defun load-section-contents-and-entropy (in sections)
  (dotimes (i (length sections))
    (let* ((sec (aref sections i))
           (bytes (section-bytes in sec))
           (ent (compute-entropy bytes)))
      (setf (elf-section-bytes sec) bytes)
      (setf (elf-section-entropy sec) ent)))
  sections)

;;;; ------------------------------------------------------------
;;;; Permissions and heuristics
;;;; ------------------------------------------------------------

(defun section-executable-p (sec)
  (logtest (elf-section-flags sec) #x4))  ; SHF_EXECINSTR

(defun section-writable-p (sec)
  (logtest (elf-section-flags sec) #x1))  ; SHF_WRITE

(defun high-entropy-sections (sections &optional (threshold 7.5))
  (remove-if-not
   (lambda (s) (> (elf-section-entropy s) threshold))
   sections))

(defun writable-executable-sections (sections)
  (remove-if-not
   (lambda (s)
     (and (section-writable-p s)
          (section-executable-p s)))
   sections))

(defun nameless-sections (sections)
  (remove-if-not
   (lambda (s)
     (or (null (elf-section-name s))
         (string= (elf-section-name s) "")))
   sections))

(defun suspicious-alignment-sections (sections)
  (remove-if-not
   (lambda (s)
     (and (> (elf-section-size s) 0)
          (< (elf-section-addralign s) 4)))
   sections))

;;;; ------------------------------------------------------------
;;;; Summary and JSON output
;;;; ------------------------------------------------------------

(defun print-summary (sections)
  (format t "~&[ELF Section Summary]~%")
  (format t "Total sections: ~D~%" (length sections))
  (format t "~%Sections:~%")
  (dolist (s sections)
    (format t "  ~A: addr=0x~X size=~D flags=0x~X entropy=~4,2f~%"
            (elf-section-name s)
            (elf-section-addr s)
            (elf-section-size s)
            (elf-section-flags s)
            (elf-section-entropy s)))
  (format t "~%High-entropy sections (>7.5): ~D~%"
          (length (high-entropy-sections sections)))
  (format t "Writable+Executable sections: ~D~%"
          (length (writable-executable-sections sections)))
  (format t "Nameless sections: ~D~%"
          (length (nameless-sections sections)))
  (format t "Suspicious alignment sections: ~D~%"
          (length (suspicious-alignment-sections sections))))

(defun json-escape (s)
  (substitute #\\ #\" (substitute #\\ #\\ s)))

(defun section-to-json (s)
  (format nil
          "{\"name\":\"~A\",\"addr\":\"0x~X\",\"size\":~D,\"flags\":\"0x~X\",\"entropy\":~4,2f}"
          (json-escape (or (elf-section-name s) ""))
          (elf-section-addr s)
          (elf-section-size s)
          (elf-section-flags s)
          (elf-section-entropy s)))

(defun sections-to-json (sections)
  (format nil "[~{~A~^,~}]" (mapcar #'section-to-json sections)))

;;;; ------------------------------------------------------------
;;;; Top-level ELF loader
;;;; ------------------------------------------------------------

(defun load-elf (path)
  (with-open-file (in path :direction :input :element-type '(unsigned-byte 8))
    (let* ((hdr (parse-elf-header in))
           (secs (load-section-headers in hdr)))
      (resolve-section-names in hdr secs)
      (load-section-contents-and-entropy in secs)
      (setf *sections* (coerce secs 'list)))))

;;;; ------------------------------------------------------------
;;;; CLI wrapper
;;;; ------------------------------------------------------------

(defun main ()
  (let ((args (copy-list sb-ext:*posix-argv*))
        file summary json analyze)
    (pop args) ; program name
    (loop while args do
      (let ((a (pop args)))
        (cond
          ((string= a "--file") (setf file (pop args)))
          ((string= a "--summary") (setf summary t))
          ((string= a "--json") (setf json t))
          ((string= a "--analyze") (setf analyze t))
          (t (format t "Unknown argument: ~A~%" a)))))
    (unless file
      (format t "Usage: elf-profiler --file <path> [--summary] [--json] [--analyze]~%")
      (return-from main))
    (load-elf file)
    (when summary
      (print-summary *sections*)
      (return-from main))
    (when json
      (format t "~A~%" (sections-to-json *sections*))
      (return-from main))
    (when analyze
      (format t "~&[ELF Anomaly Report]~%")
      (format t "High-entropy sections:~%")
      (dolist (s (high-entropy-sections *sections*))
        (format t "  ~A (entropy=~4,2f)~%" (elf-section-name s) (elf-section-entropy s)))
      (format t "~%Writable+Executable sections:~%")
      (dolist (s (writable-executable-sections *sections*))
        (format t "  ~A flags=0x~X~%" (elf-section-name s) (elf-section-flags s)))
      (format t "~%Nameless sections:~%")
      (dolist (s (nameless-sections *sections*))
        (format t "  offset=0x~X size=~D~%"
                (elf-section-offset s)
                (elf-section-size s)))
      (format t "~%Suspicious alignment sections:~%")
      (dolist (s (suspicious-alignment-sections *sections*))
        (format t "  ~A align=~D size=~D~%"
                (elf-section-name s)
                (elf-section-addralign s)
                (elf-section-size s)))
      (return-from main))
    (format t "Loaded ~D sections from ~A~%Use --summary, --json or --analyze.~%"
            (length *sections*) file)))

