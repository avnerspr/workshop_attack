import ctypes
from pathlib import Path
import gmpy2
from icecream import ic

BASE = 10


class LLLWrapper:
    def __init__(self, library_path: Path):
        """
        Initializes the LLLWrapper with the path to the shared library.

        Parameters:
            library_path (Path): Path to the shared library (e.g., Path('./liblll.so')).
        """
        self.lib = ctypes.CDLL(str(library_path.absolute()))

        # Define function prototype
        self.lib.lll.argtypes = (
            ctypes.POINTER(ctypes.POINTER(ctypes.c_char_p)),  # 2D array of strings
            ctypes.c_int,  # Number of rows
            ctypes.POINTER(ctypes.c_int),  # Number of columns per row
            ctypes.c_double,  # delta
        )
        self.lib.lll.restype = ctypes.POINTER(
            ctypes.POINTER(ctypes.POINTER(ctypes.c_char))
        )

        self.lib.free_matrix.argtypes = (
            ctypes.POINTER(
                ctypes.POINTER(ctypes.POINTER(ctypes.c_char))
            ),  # 2D array of strings
            ctypes.c_int,  # Number of rows
            ctypes.POINTER(ctypes.c_int),  # Number of columns per row
        )
        self.lib.free_matrix.restype = None

    def lll(self, matrix: list[list[int]], delta: float = 0.75) -> list[list[int]]:
        """
        Process a list of lists of strings via the LLL C function.

        Parameters:
            string_matrix (list[list[str]]): List of lists of strings.

        Returns:
            list[list[str]]: Modified list of lists of strings.
        """
        string_matrix: list[list[str]] = [[str(x) for x in row] for row in matrix]

        num_rows = len(string_matrix)
        num_cols = (ctypes.c_int * num_rows)(*[len(row) for row in string_matrix])

        # Convert to C-compatible 2D array of `char*`
        c_string_matrix = (ctypes.POINTER(ctypes.c_char_p) * num_rows)()
        for i, row in enumerate(string_matrix):
            c_string_matrix[i] = (ctypes.c_char_p * len(row))(
                *[s.encode("utf-8") for s in row]
            )

        c_delta = ctypes.c_double(delta)

        # Call the C++ function (modifies in-place)
        c_ans = self.lib.lll(c_string_matrix, num_rows, num_cols, c_delta)

        result = [
            [
                int(ctypes.cast(c_ans[i][j], ctypes.c_char_p).value.decode(), BASE)
                for j in range(len(string_matrix[i]))
            ]
            for i in range(num_rows)
        ]
        self.lib.free_matrix(c_ans, num_rows, num_cols)

        return result


if __name__ == "__main__":
    wrapper = LLLWrapper(Path("liblll.so"))
    result = wrapper.lll([[1, 2, 3, 4], [3, 1, 4, 1], [5, 9, 2, 6], [5, 3, 5, 8]])
    ic(result)
