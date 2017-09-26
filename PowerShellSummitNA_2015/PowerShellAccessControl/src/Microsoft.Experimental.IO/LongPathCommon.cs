//     Copyright (c) Microsoft Corporation.  All rights reserved.
using System;
using System.Diagnostics.Contracts;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using ROE.ThirdParty.Microsoft.Experimental.IO.Interop;

namespace ROE.ThirdParty.Microsoft.Experimental.IO {

    internal static class LongPathCommon {
        internal static string NormalizeSearchPattern(string searchPattern) {
            if (String.IsNullOrEmpty(searchPattern) || searchPattern == ".")
                return "*";

            return searchPattern;
        }

        internal static string NormalizeLongPath(string path) {

            return NormalizeLongPath(path, "path");
        }

        // Normalizes path (can be longer than MAX_PATH) and adds \\?\ long path prefix
        internal static string NormalizeLongPath(string path, string parameterName) {

            if (path == null)
                throw new ArgumentNullException(parameterName);

            if (path.Length == 0)
                throw new ArgumentException(String.Format(CultureInfo.CurrentCulture, "'{0}' cannot be an empty string.", parameterName), parameterName);

            StringBuilder buffer = new StringBuilder(path.Length + 1); // Add 1 for NULL
            uint length = Microsoft.Experimental.IO.Interop.NativeMethods.GetFullPathName(path, (uint)buffer.Capacity, buffer, IntPtr.Zero);
            if (length > buffer.Capacity) {
                // Resulting path longer than our buffer, so increase it

                buffer.Capacity = (int)length;
                length = Microsoft.Experimental.IO.Interop.NativeMethods.GetFullPathName(path, length, buffer, IntPtr.Zero);
            }

            if (length == 0) {
                throw LongPathCommon.GetExceptionFromLastWin32Error(parameterName);
            }

            if (length > Microsoft.Experimental.IO.Interop.NativeMethods.MAX_LONG_PATH) {
                throw LongPathCommon.GetExceptionFromWin32Error(Microsoft.Experimental.IO.Interop.NativeMethods.ERROR_FILENAME_EXCED_RANGE, parameterName);
            }

            return AddLongPathPrefix(buffer.ToString());
        }

        private static bool TryNormalizeLongPath(string path, out string result) {

            try {

                result = NormalizeLongPath(path);
                return true;
            }
            catch (ArgumentException) {
            }
            catch (PathTooLongException) {
            }

            result = null;
            return false;
        }

        private static string AddLongPathPrefix(string path) {

		   if (path.StartsWith (@"\\")) { // if we have been passed a UNC style path (server) prepend \\?\UNC\ but we need to replace the \\ with a single \
				return Microsoft.Experimental.IO.Interop.NativeMethods.LongPathUNCPrefix + path.Substring(2);
			}
			else //assume a standard path (ie C:\windows) and prepend \\?\ to it
			{
				return Microsoft.Experimental.IO.Interop.NativeMethods.LongPathPrefix + path;
			}
        }

        internal static string RemoveLongPathPrefix(string normalizedPath) {

			if (normalizedPath.StartsWith(Microsoft.Experimental.IO.Interop.NativeMethods.LongPathUNCPrefix)) // if we have been supplied a path with the \\?\UNC\ prefix
			{
				return @"\\" + normalizedPath.Substring(Microsoft.Experimental.IO.Interop.NativeMethods.LongPathUNCPrefix.Length);
			}
			else if (normalizedPath.StartsWith(Microsoft.Experimental.IO.Interop.NativeMethods.LongPathPrefix))  // if we have been supplied with the \\?\ prefix
			{
				return  normalizedPath.Substring(Microsoft.Experimental.IO.Interop.NativeMethods.LongPathPrefix.Length);
			}

			return normalizedPath;
        }

        internal static bool Exists(string path, out bool isDirectory) {

            string normalizedPath;
            if (TryNormalizeLongPath(path, out normalizedPath)) {

                FileAttributes attributes;
                int errorCode = TryGetFileAttributes(normalizedPath, out attributes);
                if (errorCode == 0) {
                    isDirectory = LongPathDirectory.IsDirectory(attributes);
                    return true;
                }
            }

            isDirectory = false;
            return false;
        }

        internal static int TryGetDirectoryAttributes(string normalizedPath, out FileAttributes attributes) {

            int errorCode = TryGetFileAttributes(normalizedPath, out attributes);
            if (!LongPathDirectory.IsDirectory(attributes))
                errorCode = Microsoft.Experimental.IO.Interop.NativeMethods.ERROR_DIRECTORY;

            return errorCode;
        }

        internal static int TryGetFileAttributes(string normalizedPath, out FileAttributes attributes) {
            // NOTE: Don't be tempted to use FindFirstFile here, it does not work with root directories

            attributes = Microsoft.Experimental.IO.Interop.NativeMethods.GetFileAttributes(normalizedPath);
            if ((int)attributes == Microsoft.Experimental.IO.Interop.NativeMethods.INVALID_FILE_ATTRIBUTES)
                return Marshal.GetLastWin32Error();

            return 0;
        }

        internal static Exception GetExceptionFromLastWin32Error() {
            return GetExceptionFromLastWin32Error("path");
        }

        internal static Exception GetExceptionFromLastWin32Error(string parameterName) {
            return GetExceptionFromWin32Error(Marshal.GetLastWin32Error(), parameterName);
        }

        internal static Exception GetExceptionFromWin32Error(int errorCode) {
            return GetExceptionFromWin32Error(errorCode, "path");
        }

        internal static Exception GetExceptionFromWin32Error(int errorCode, string parameterName) {

            string message = GetMessageFromErrorCode(errorCode);

            switch (errorCode) {

                case Microsoft.Experimental.IO.Interop.NativeMethods.ERROR_FILE_NOT_FOUND:
                    return new FileNotFoundException(message);

                case Microsoft.Experimental.IO.Interop.NativeMethods.ERROR_PATH_NOT_FOUND:
                    return new DirectoryNotFoundException(message);

                case Microsoft.Experimental.IO.Interop.NativeMethods.ERROR_ACCESS_DENIED:
                    return new UnauthorizedAccessException(message);

                case Microsoft.Experimental.IO.Interop.NativeMethods.ERROR_FILENAME_EXCED_RANGE:
                    return new PathTooLongException(message);

                case Microsoft.Experimental.IO.Interop.NativeMethods.ERROR_INVALID_DRIVE:
                    return new System.IO.DriveNotFoundException(message);

                case Microsoft.Experimental.IO.Interop.NativeMethods.ERROR_OPERATION_ABORTED:
                    return new OperationCanceledException(message);

                case Microsoft.Experimental.IO.Interop.NativeMethods.ERROR_INVALID_NAME:
                    return new ArgumentException(message, parameterName);

                default:
                    return new IOException(message, Microsoft.Experimental.IO.Interop.NativeMethods.MakeHRFromErrorCode(errorCode));

            }
        }

        private static string GetMessageFromErrorCode(int errorCode) {

            StringBuilder buffer = new StringBuilder(512);

            int bufferLength = Microsoft.Experimental.IO.Interop.NativeMethods.FormatMessage(Microsoft.Experimental.IO.Interop.NativeMethods.FORMAT_MESSAGE_IGNORE_INSERTS | Microsoft.Experimental.IO.Interop.NativeMethods.FORMAT_MESSAGE_FROM_SYSTEM | Microsoft.Experimental.IO.Interop.NativeMethods.FORMAT_MESSAGE_ARGUMENT_ARRAY, IntPtr.Zero, errorCode, 0, buffer, buffer.Capacity, IntPtr.Zero);

            Contract.Assert(bufferLength != 0);

            return buffer.ToString();
        }
    }
}
