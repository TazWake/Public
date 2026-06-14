;;;; profiler.lisp
;;;; ELF Section Forensic Profiler — 64-bit, little-endian ELF
;;;;
;;;; Parses the section-header table of an ELF executable/shared object and
;;;; profiles each section (entropy, permissions, alignment) to surface signs of
;;;; packing, encryption, or header tampering. Scope is deliberately narrow:
;;;; ELFCLASS64 + ELFDATA2LSB only (the common x86-64 / aarch64 case).

(defpackage :profiler
  (:use :cl)
  (:export :main))

(in-package :profiler)

;;;; ------------------------------------------------------------
;;;; Low-level binary helpers (little-endian)
;;;; ------------------------------------------------------------
;;;; Each reader assembles a fixed-width little-endian integer from raw bytes
;;;; (low-order byte first, matching ELFDATA2LSB). They return NIL on a short
;;;; read / EOF rather than signalling, so a truncated file fails gracefully
;;;; at the parse layer instead of erroring deep in I/O.

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

;; Read up to N bytes into a fresh vector. On EOF it returns the partially
;; filled vector (trailing elements left at 0) rather than erroring, so callers
;; that pass an over-long size (e.g. a corrupt sh_size) still get a usable buffer.
(defun read-bytes (in n)
  (let ((vec (make-array n :element-type '(unsigned-byte 8))))
    (dotimes (i n vec)
      (let ((b (read-byte in nil nil)))
        (unless b
          (return vec))
        (setf (aref vec i) b)))))

;; Absolute seek -- ELF section/string-table contents are located by file offset.
(defun seek (in pos)
  (file-position in pos))

;;;; ------------------------------------------------------------
;;;; Data structures
;;;; ------------------------------------------------------------

;; Subset of Elf64_Ehdr we actually need to walk the section table:
;;   shoff      -> file offset of the section-header table (e_shoff)
;;   shentsize  -> size of one section header (e_shentsize)
;;   shnum      -> number of section headers (e_shnum)
;;   shstrndx   -> index of the section-name string table (.shstrtab)
(defstruct elf-header
  entry
  shoff
  shentsize
  shnum
  shstrndx)

;; One Elf64_Shdr, plus two derived fields populated after parsing:
;;   bytes   -> the section's raw contents (read lazily in a second pass)
;;   entropy -> Shannon entropy of those bytes, in bits/byte (0.0-8.0)
;; NAME starts as the sh_name string-table offset and is later rewritten in
;; place to the resolved string (see RESOLVE-SECTION-NAMES).
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

;; Module-level state populated by MAIN (mirrors the other tools' globals so the
;; CLI dispatch and an interactive REPL workflow stay simple).
(defparameter *sections* nil)

;;;; ------------------------------------------------------------
;;;; ELF header parsing (64-bit, little-endian)
;;;; ------------------------------------------------------------

;; Reads the 64-byte Elf64_Ehdr from the start of the stream, validating the
;; e_ident magic/class/data fields and keeping only the section-table locators.
;; Assumes IN is positioned at offset 0.
(defun parse-elf-header (in)
  ;; e_ident[0..3]: the "\x7FELF" magic.
  (let ((magic (read-bytes in 4)))
    (unless (and (= (aref magic 0) #x7F)
                 (= (aref magic 1) (char-code #\E))
                 (= (aref magic 2) (char-code #\L))
                 (= (aref magic 3) (char-code #\F)))
      (error "Not an ELF file.")))
  ;; e_ident[4]=EI_CLASS (2 = ELFCLASS64), e_ident[5]=EI_DATA (1 = ELFDATA2LSB).
  ;; This profiler only understands 64-bit little-endian; reject anything else
  ;; up front rather than silently misreading the multi-byte fields below.
  (let ((class (read-u8 in))
        (data (read-u8 in)))
    (unless (= class 2)
      (error "Only 64-bit ELF supported."))
    (unless (= data 1)
      (error "Only little-endian ELF supported.")))
  ;; Skip the remaining 10 bytes of the 16-byte e_ident (version/OSABI/pad).
  (read-bytes in 10)
  ;; e_type, e_machine, e_version -- not needed, consumed to stay aligned.
  (read-u16 in)
  (read-u16 in)
  (read-u32 in)
  ;; Remaining Elf64_Ehdr fields, in on-disk order. We keep e_entry plus the
  ;; section-table locators; the program-header and size fields are read only to
  ;; advance the stream and are discarded (see DECLARE IGNORE).
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

;; Reads one Elf64_Shdr at the stream's current position. Fields are in on-disk
;; order; NAME here is sh_name (a byte offset into .shstrtab, resolved later).
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

;; Seek to e_shoff and read the e_shnum section headers sequentially into a
;; vector. Assumes headers are contiguous (the normal layout); we don't seek per
;; header by e_shentsize, so a file with unusual shentsize padding won't parse.
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

;; The section-name string table (.shstrtab, index e_shstrndx) is a blob of
;; NUL-terminated strings; each section's sh_name is a byte offset into it.
;; Walk from that offset to the next NUL and rewrite NAME in place from the
;; offset to the resolved string. An out-of-range offset leaves NAME numeric,
;; which the heuristics treat as a "nameless" (tampered) section.
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

;; Shannon entropy over the byte-value distribution, in bits/byte. Ranges from
;; 0.0 (all one value) to 8.0 (uniform over 256 values). High values indicate
;; compressed/encrypted/packed data; ordinary code and text sit well below 8.
;; H = -sum(p * log2(p)) over the 256 possible byte values, computed here as
;; sum(p * log2(1/p)) which is equivalent and avoids the leading negation.
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

;; Second pass over the parsed headers: read each section's bytes from disk and
;; cache them plus their entropy on the struct. Separated from header parsing so
;; the (sequential) header read isn't interleaved with content seeks.
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

;; sh_flags bit tests. The two we care about for W^X reasoning.
(defun section-executable-p (sec)
  (logtest (elf-section-flags sec) #x4))  ; SHF_EXECINSTR

(defun section-writable-p (sec)
  (logtest (elf-section-flags sec) #x1))  ; SHF_WRITE

;; Heuristic: entropy near the 8.0 ceiling. The 7.5 default is a common
;; packed/encrypted-payload threshold; lower it to catch lighter obfuscation,
;; raise it to cut false positives from legitimately dense data.
(defun high-entropy-sections (sections &optional (threshold 7.5))
  (remove-if-not
   (lambda (s) (> (elf-section-entropy s) threshold))
   sections))

;; Heuristic: a section flagged both writable and executable. Toolchains emit
;; W^X-clean binaries, so SHF_WRITE+SHF_EXECINSTR together is a tampering /
;; self-modifying-code tell.
(defun writable-executable-sections (sections)
  (remove-if-not
   (lambda (s)
     (and (section-writable-p s)
          (section-executable-p s)))
   sections))

;; Heuristic: a section whose name didn't resolve to a string -- either the
;; sh_name offset was out of range (left numeric) or the entry is empty. Common
;; with stripped or hand-forged section headers used to frustrate analysis.
(defun nameless-sections (sections)
  (remove-if-not
   (lambda (s)
     (or (null (elf-section-name s))
         (numberp (elf-section-name s))
         (string= (elf-section-name s) "")))
   sections))

;; Heuristic: a non-empty section with sub-word (sh_addralign < 4) alignment.
;; Real compiled sections are typically aligned to at least 4 bytes; tiny/odd
;; alignment suggests a manually injected or hand-built section.
(defun suspicious-alignment-sections (sections)
  (remove-if-not
   (lambda (s)
     (and (> (elf-section-size s) 0)
          (< (elf-section-addralign s) 4)))
   sections))

;;;; ------------------------------------------------------------
;;;; Summary and JSON output
;;;; ------------------------------------------------------------

;; A section's NAME is a string once resolved, but stays a numeric sh_name
;; offset if resolution failed (out-of-range). Render that as "<unnamed>" so
;; both output paths show a string and JSON never tries to escape a number.
(defun section-display-name (s)
  (let ((n (elf-section-name s)))
    (if (stringp n) n "<unnamed>")))

(defun print-summary (sections)
  (format t "~&[ELF Section Summary]~%")
  (format t "Total sections: ~D~%" (length sections))
  (format t "~%Sections:~%")
  (dolist (s sections)
    (format t "  ~A: addr=0x~X size=~D flags=0x~X entropy=~4,2f~%"
            (section-display-name s)
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

;; LIMITATION (shared with the other tools): SUBSTITUTE is char-for-char and
;; cannot expand " into \". Safe here because ELF section names are short
;; identifiers (.text, .data, ...) that never contain " or \.
(defun json-escape (s)
  (substitute #\\ #\" (substitute #\\ #\\ s)))

(defun section-to-json (s)
  (format nil
          "{\"name\":\"~A\",\"addr\":\"0x~X\",\"size\":~D,\"flags\":\"0x~X\",\"entropy\":~4,2f}"
          (json-escape (section-display-name s))
          (elf-section-addr s)
          (elf-section-size s)
          (elf-section-flags s)
          (elf-section-entropy s)))

(defun sections-to-json (sections)
  (format nil "[~{~A~^,~}]" (mapcar #'section-to-json sections)))

;;;; ------------------------------------------------------------
;;;; Top-level ELF loader
;;;; ------------------------------------------------------------

;; Orchestrates the full parse: header -> section headers -> name resolution ->
;; content+entropy, then stores the sections as a list in *SECTIONS*. Opens the
;; file as raw bytes (element-type (unsigned-byte 8)); a non-ELF or non-64-bit
;; little-endian file errors out in PARSE-ELF-HEADER.
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

;; CLI entry point (exported; used as the :toplevel of a saved executable, or
;; called directly under `sbcl --load`). Output modes are mutually exclusive and
;; checked in priority order -- summary > json > analyze -- each returning early,
;; so passing several flags uses the first match.
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
      (format t "Usage: profiler --file <path> [--summary] [--json] [--analyze]~%")
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
        (format t "  ~A (entropy=~4,2f)~%" (section-display-name s) (elf-section-entropy s)))
      (format t "~%Writable+Executable sections:~%")
      (dolist (s (writable-executable-sections *sections*))
        (format t "  ~A flags=0x~X~%" (section-display-name s) (elf-section-flags s)))
      (format t "~%Nameless sections:~%")
      (dolist (s (nameless-sections *sections*))
        (format t "  offset=0x~X size=~D~%"
                (elf-section-offset s)
                (elf-section-size s)))
      (format t "~%Suspicious alignment sections:~%")
      (dolist (s (suspicious-alignment-sections *sections*))
        (format t "  ~A align=~D size=~D~%"
                (section-display-name s)
                (elf-section-addralign s)
                (elf-section-size s)))
      (return-from main))
    (format t "Loaded ~D sections from ~A~%Use --summary, --json or --analyze.~%"
            (length *sections*) file)))

