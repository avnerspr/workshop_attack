import ctypes
import numpy as np
from pathlib import Path


class LLLWrapper:
    def __init__(self, library_path: Path):
        """
        Initializes the LLLWrapper with the path to the shared library.

        Parameters:
            library_path (Path): Path to the shared library (e.g., Path('./liblll.so')).
        """
        self.lib = ctypes.CDLL(str(library_path.absolute()))

        # Define the function prototype
        self.lib.lll.argtypes = (
            ctypes.POINTER(ctypes.c_double),
            ctypes.c_int,
            ctypes.c_int,
        )
        self.lib.lll.restype = None

    def lll(self, lattice: list[list[int]]) -> list[list[int]]:
        """
        Perform LLL reduction on the provided lattice.

        Parameters:
            lattice (list[list[int]]): The input lattice as a 2D list of integers.

        Returns:
            list[list[int]]: The modified lattice after LLL reduction.
        """
        # Convert the 2D list to a NumPy array of type double
        lattice_array = np.array(lattice, dtype=np.float64)
        num_of_vectors, vector_dimension = lattice_array.shape

        # Flatten the array for row-major order (C-style)
        flat_lattice = lattice_array.flatten()

        # Convert to ctypes-compatible pointer
        flat_lattice_ctypes = flat_lattice.ctypes.data_as(
            ctypes.POINTER(ctypes.c_double)
        )

        # Call the C++ LLL function
        self.lib.lll(flat_lattice_ctypes, num_of_vectors, vector_dimension)

        # Reshape the flat array back to 2D and convert to a Python list
        modified_lattice = flat_lattice.reshape(
            (num_of_vectors, vector_dimension)
        ).tolist()

        return modified_lattice
