import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import * as api from "../../services/api";
import ReportDownloads from "./ReportDownloads";

const file = new File(["workbook"], "events.xlsx");

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("ReportDownloads", () => {
  it("downloads a report using a temporary object URL", async () => {
    const createObjectURL = vi.fn().mockReturnValue("blob:report");
    const revokeObjectURL = vi.fn();
    const click = vi
      .spyOn(HTMLAnchorElement.prototype, "click")
      .mockImplementation(() => undefined);
    vi.stubGlobal("URL", {
      createObjectURL,
      revokeObjectURL,
    });
    vi.spyOn(api, "requestExecutiveReport").mockResolvedValue({
      blob: new Blob(["%PDF-1.4 test"], { type: "application/pdf" }),
      filename: "SOC_L2_Informe_Ejecutivo.pdf",
    });
    vi.spyOn(api, "requestTechnicalReport");

    render(
      <ReportDownloads file={file} expectedFileSha256={"a".repeat(64)} />,
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Descargar informe ejecutivo" }),
    );

    expect(await screen.findByRole("status")).toHaveTextContent(
      "Informe descargado correctamente.",
    );
    expect(click).toHaveBeenCalledOnce();
    expect(createObjectURL).toHaveBeenCalledWith(expect.any(Blob));
    expect(api.requestExecutiveReport).toHaveBeenCalledWith(
      file,
      "a".repeat(64),
      expect.any(AbortSignal),
    );
    expect(api.requestTechnicalReport).not.toHaveBeenCalled();
    await waitFor(() => expect(revokeObjectURL).toHaveBeenCalledWith("blob:report"));
  });

  it("keeps report actions independent and blocks duplicate requests", async () => {
    let resolveReport!: (value: api.ReportDownload) => void;
    const pending = new Promise<api.ReportDownload>((resolve) => {
      resolveReport = resolve;
    });
    const request = vi
      .spyOn(api, "requestExecutiveReport")
      .mockReturnValue(pending);
    vi.spyOn(api, "requestTechnicalReport").mockResolvedValue({
      blob: new Blob(["%PDF-1.4 test"], { type: "application/pdf" }),
      filename: "SOC_L2_Informe_Tecnico.pdf",
    });
    vi.stubGlobal("URL", {
      createObjectURL: vi.fn().mockReturnValue("blob:report"),
      revokeObjectURL: vi.fn(),
    });
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(
      () => undefined,
    );

    render(<ReportDownloads file={file} expectedFileSha256="expected-hash" />);
    const executive = screen.getByRole("button", {
      name: "Descargar informe ejecutivo",
    });
    fireEvent.click(executive);
    fireEvent.click(executive);

    expect(request).toHaveBeenCalledOnce();
    expect(
      screen.getByRole("button", { name: "Descargar informe técnico" }),
    ).toBeEnabled();
    expect(
      screen.getByRole("button", { name: /Generando informe ejecutivo/ }),
    ).toBeDisabled();

    resolveReport({
      blob: new Blob(["%PDF-1.4 test"], { type: "application/pdf" }),
      filename: "SOC_L2_Informe_Ejecutivo.pdf",
    });
    await screen.findByRole("status");
  });

  it("shows a hash mismatch error and allows retry", async () => {
    const request = vi
      .spyOn(api, "requestTechnicalReport")
      .mockRejectedValueOnce(
        new api.ApiError(
          "El archivo no coincide con el análisis actual.",
          409,
          "file_hash_mismatch",
          "http",
        ),
      )
      .mockResolvedValueOnce({
        blob: new Blob(["%PDF-1.4 test"], { type: "application/pdf" }),
        filename: "SOC_L2_Informe_Tecnico.pdf",
      });
    vi.stubGlobal("URL", {
      createObjectURL: vi.fn().mockReturnValue("blob:report"),
      revokeObjectURL: vi.fn(),
    });
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(
      () => undefined,
    );

    render(<ReportDownloads file={file} expectedFileSha256="expected-hash" />);
    fireEvent.click(
      screen.getByRole("button", { name: "Descargar informe técnico" }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Volvé a analizarlo antes de generar el informe.",
    );

    fireEvent.click(
      screen.getByRole("button", { name: "Descargar informe técnico" }),
    );
    expect(await screen.findByRole("status")).toHaveTextContent(
      "Informe descargado correctamente.",
    );
    expect(request).toHaveBeenCalledTimes(2);
  });

  it("aborts an in-progress export when the associated analysis unmounts", () => {
    const request = vi
      .spyOn(api, "requestExecutiveReport")
      .mockReturnValue(new Promise(() => undefined));
    const { unmount } = render(
      <ReportDownloads file={file} expectedFileSha256="expected-hash" />,
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Descargar informe ejecutivo" }),
    );
    const signal = request.mock.calls[0]?.[2];
    expect(signal).toBeDefined();
    expect(signal?.aborted).toBe(false);

    unmount();
    expect(signal?.aborted).toBe(true);
  });
});
