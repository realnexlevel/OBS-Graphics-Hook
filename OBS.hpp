namespace OBS
{
	uintptr_t DetourAttachAddress = 0, DetourTransactionBeginAddress = 0, DetourTransactionCommitAddress = 0;

	static auto GetBase() -> uintptr_t
	{
		return
			reinterpret_cast<uintptr_t>(LI_FN(GetModuleHandleA)(Xor("graphics-hook64.dll")));
	}

	static auto SwapPresentScenePointer(PVOID NewHook) -> PVOID
	{
		auto OBSModule = OBS::GetBase();
		if (OBSModule == NULL)
		{
			LI_FN(MessageBoxA)((HWND)nullptr, Xor("OBS module is not loaded."), Xor("Failure"), MB_ICONERROR);
			return nullptr;
		}

		auto SizeOfImage = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<std::uint8_t*>(OBSModule) +
			reinterpret_cast<PIMAGE_DOS_HEADER>(OBSModule)->e_lfanew)->OptionalHeader.SizeOfImage;

		auto addr = Util::PatternScan(
			OBSModule,
			SizeOfImage,
			L"\x48\x8B\x05\x00\x00\x00\x00\xFF\xD0\xC7\x04\x33\x00\x00\x00\x00\xE9",
			L"xxx????xxxxx????x"
		);

		if (addr == NULL)
		{
			LI_FN(MessageBoxA)((HWND)nullptr, Xor("Failed to get reference to the present original function pointer."), Xor("Failure"), MB_ICONERROR);
			return nullptr;
		}

		addr = RVA(addr, 7);

		return _InterlockedExchangePointer(reinterpret_cast<volatile PVOID*>(addr), NewHook);
	}

	static auto DetourAttach(_Inout_ PVOID* ppPointer, _In_ PVOID pDetour) -> uintptr_t
	{
		if (OBS::DetourAttachAddress == NULL)
		{
			auto OBSModule = OBS::GetBase();
			if (OBSModule == NULL)
			{
				LI_FN(MessageBoxA)((HWND)nullptr, Xor("OBS module is not loaded."), Xor("Failure"), MB_ICONERROR);
				return 0;
			}

			auto SizeOfImage = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<std::uint8_t*>(OBSModule) +
				reinterpret_cast<PIMAGE_DOS_HEADER>(OBSModule)->e_lfanew)->OptionalHeader.SizeOfImage;

			OBS::DetourAttachAddress = Util::PatternScan(
				OBSModule,
				SizeOfImage,
				L"\xE8\x00\x00\x00\x00\x48\x85\xDB\x74\x1A",
				L"x????xxxxx"
			);

			if (OBS::DetourAttachAddress == NULL)
			{
				LI_FN(MessageBoxA)((HWND)nullptr, Xor("Failed to resolve DetourAttach function."), Xor("Failure"), MB_ICONERROR);
				return 0;
			}

			OBS::DetourAttachAddress = RVA(OBS::DetourAttachAddress, 5);
		}

		return reinterpret_cast<LONG(__fastcall*)(_Inout_ PVOID * ppPointer, _In_ PVOID pDetour)>
			(OBS::DetourAttachAddress)(ppPointer, pDetour);
	}

	static auto DetourTransactionBegin() -> LONG
	{
		if (OBS::DetourTransactionBeginAddress == NULL)
		{
			auto OBSModule = OBS::GetBase();
			if (OBSModule == NULL)
			{
				LI_FN(MessageBoxA)((HWND)nullptr, Xor("OBS module is not loaded."), Xor("Failure"), MB_ICONERROR);
				return 0;
			}

			auto SizeOfImage = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<std::uint8_t*>(OBSModule) +
				reinterpret_cast<PIMAGE_DOS_HEADER>(OBSModule)->e_lfanew)->OptionalHeader.SizeOfImage;

			OBS::DetourTransactionBeginAddress = Util::PatternScan(
				OBSModule,
				SizeOfImage,
				L"\xE8\x00\x00\x00\x00\x48\x8B\x43\x70",
				L"x????xxxx"
			);

			if (OBS::DetourTransactionBeginAddress == NULL)
			{
				LI_FN(MessageBoxA)((HWND)nullptr, Xor("Failed to resolve DetourTransactionBegin function."), Xor("Failure"), MB_ICONERROR);
				return 0;
			}

			OBS::DetourTransactionBeginAddress = RVA(OBS::DetourTransactionBeginAddress, 5);
		}

		reinterpret_cast<LONG(__fastcall*)(VOID)>(OBS::DetourTransactionBeginAddress)();
	}

	static auto DetourTransactionCommit() -> LONG
	{
		if (OBS::DetourTransactionCommitAddress == NULL)
		{
			auto OBSModule = OBS::GetBase();
			if (OBSModule == NULL)
			{
				LI_FN(MessageBoxA)((HWND)nullptr, Xor("OBS module is not loaded."), Xor("Failure"), MB_ICONERROR);
				return 0;
			}

			auto SizeOfImage = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<std::uint8_t*>(OBSModule) +
				reinterpret_cast<PIMAGE_DOS_HEADER>(OBSModule)->e_lfanew)->OptionalHeader.SizeOfImage;

			OBS::DetourTransactionCommitAddress = Util::PatternScan(
				OBSModule,
				SizeOfImage,
				L"\xE8\x00\x00\x00\x00\x85\xC0\x75\x34",
				L"x????xxxx"
			);

			if (OBS::DetourTransactionCommitAddress == NULL)
			{
				LI_FN(MessageBoxA)((HWND)nullptr, Xor("Failed to resolve DetourTransactionCommit function."), Xor("Failure"), MB_ICONERROR);
				return 0;
			}

			OBS::DetourTransactionCommitAddress = RVA(OBS::DetourTransactionCommitAddress, 5);
		}

		reinterpret_cast<LONG(__fastcall*)(VOID)>(OBS::DetourTransactionCommitAddress)();
	}

	static auto DetourPresentScene(PVOID& Original, PVOID NewFunction)
	{
		auto OBSModule = OBS::GetBase();
		if (OBSModule == NULL)
		{
			LI_FN(MessageBoxA)((HWND)nullptr, Xor("OBS module is not loaded."), Xor("Failure"), MB_ICONERROR);
			return;
		}

		auto SizeOfImage = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<std::uint8_t*>(OBSModule) +
			reinterpret_cast<PIMAGE_DOS_HEADER>(OBSModule)->e_lfanew)->OptionalHeader.SizeOfImage;

		auto addr = Util::PatternScan(
			OBSModule,
			SizeOfImage,
			L"\x48\x89\x74\x24\x00\x57\x41\x54\x41\x57",
			L"xxxx?xxxxx"
		);

		if (addr == NULL)
		{
			LI_FN(MessageBoxA)((HWND)nullptr, Xor("Failed to resolve PresentScene function."), Xor("Failure"), MB_ICONERROR);
			return;
		}

		OBS::DetourTransactionBegin();

		Original = (decltype(Original))addr;
		OBS::DetourAttach(&(PVOID&)Original, NewFunction);

		// Commit all hooks...
		OBS::DetourTransactionCommit();
	}
}
