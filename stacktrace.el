;;
;; stacktrace.el
;;
;; Author: Markku Rossi <mtr@iki.fi>
;;
;; Actually this is ripped from GNU Emacs' `gud.el' so copyright and author
;; information are as with `gud.el'.
;;
;; This file is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation; either version 3, or (at your option)
;; any later version.
;;
;; This file is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.
;; You should have received a copy of the GNU General Public License
;; along with GNU Emacs; see the file COPYING.  If not, write to the
;; Free Software Foundation, Inc., 59 Temple Place - Suite 330,
;; Boston, MA 02111-1307, USA.
;;

(require 'gud)

;; History of argument lists passed to stacktrace.
(defvar gud-stacktrace-history nil)

(defun gud-stacktrace-massage-args (file args)
  (cons "-f" args))

(defvar gud-stacktrace-marker-regexp
  ;; This used to use path-separator instead of ":";
  ;; however, we found that on both Windows 32 and MSDOS
  ;; a colon is correct here.
  (concat "\032\032\\(.:?[^" ":" "\n]*\\)" ":"
	  "\\([0-9]*\\)" ":" ".*\n"))

(defun gud-stacktrace-marker-filter (string)
  (setq gud-marker-acc (concat gud-marker-acc string))
  (let ((output ""))

    ;; Process all the complete markers in this chunk.
    (while (string-match gud-stacktrace-marker-regexp gud-marker-acc)
      (setq

       ;; Extract the frame position from the marker.
       gud-last-frame
       (cons (substring gud-marker-acc (match-beginning 1) (match-end 1))
	     (string-to-int (substring gud-marker-acc
				       (match-beginning 2)
				       (match-end 2))))

       ;; Append any text before the marker to the output we're going
       ;; to return - we don't include the marker in this text.
       output (concat output
		      (substring gud-marker-acc 0 (match-beginning 0)))

       ;; Set the accumulator to the remaining text.
       gud-marker-acc (substring gud-marker-acc (match-end 0))))

    ;; Does the remaining text look like it might end with the
    ;; beginning of another marker?  If it does, then keep it in
    ;; gud-marker-acc until we receive the rest of it.  Since we
    ;; know the full marker regexp above failed, it's pretty simple to
    ;; test for marker starts.
    (if (string-match "\032.*\\'" gud-marker-acc)
	(progn
	  ;; Everything before the potential marker start can be output.
	  (setq output (concat output (substring gud-marker-acc
						 0 (match-beginning 0))))

	  ;; Everything after, we save, to combine with later input.
	  (setq gud-marker-acc
		(substring gud-marker-acc (match-beginning 0))))

      (setq output (concat output gud-marker-acc)
	    gud-marker-acc ""))

    output))

(defun gud-stacktrace-find-file (f)
  (find-file-noselect f 'nowarn))

(defvar stacktrace-minibuffer-local-map nil
  "Keymap for minibuffer prompting of stacktrace startup command.")
(if stacktrace-minibuffer-local-map
    ()
  (setq stacktrace-minibuffer-local-map (copy-keymap minibuffer-local-map))
  (define-key
    stacktrace-minibuffer-local-map "\C-i" 'comint-dynamic-complete-filename))

;;;###autoload
(defun stacktrace (command-line)
  (interactive
   (list (read-from-minibuffer "Run stacktrace (like this): "
			       (if (consp gud-stacktrace-history)
				   (car gud-stacktrace-history)
				 "stacktrace ")
			       stacktrace-minibuffer-local-map nil
			       '(gud-stacktrace-history . 1))))

  (gud-common-init command-line 'gud-stacktrace-massage-args
		   'gud-stacktrace-marker-filter 'gud-stacktrace-find-file)
  (setq comint-prompt-regexp "^(.*stacktrace[+]?) *")
  (setq paragraph-start comint-prompt-regexp)
  ;; (run-hooks 'gdb-mode-hook)
  )
