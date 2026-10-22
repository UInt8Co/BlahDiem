import BlahDiem
import DiemProfileHostingClient
import JavaScriptKit

func hostingError(_ error: any Error) -> JSException {
  if let error = error as? JSException { return error }
  // Malformed Diem wire records are invalid hosting responses or publication inputs.
  var code = "invalidResponse"
  if let error = error as? DiemError, error == .unsupportedAlgorithm { code = "unsupportedAlgorithm" }
  var status: Int?
  var problem: HostingProblem?
  if let error = error as? ProfileHostingError {
    switch error {
    case .cancelled: code = "cancelled"
    case .invalidResponse: code = "invalidResponse"
    case .unexpectedStatus(let value): code = "unexpectedStatus"; status = value
    case .domainMismatch, .domainsMismatch: code = "domainMismatch"
    case .unsupportedAlgorithm: code = "unsupportedAlgorithm"
    case .invalidLabel: code = "invalidLabel"
    case .nameTaken: code = "nameTaken"
    case .unsolvable: code = "unsolvable"
    case .invalidProof: code = "invalidProof"
    case .noHostedName: code = "noHostedName"
    case .hostNotListed: code = "hostNotListed"
    case .tooLarge: code = "tooLarge"
    case .publishedMismatch: code = "publishedMismatch"
    case .problem(let value): code = "hostingProblem"; problem = value
    }
  }
  let exception = JSException(message: code)
  let object = exception.thrownValue.object!
  object.type = .string(code)
  if let status { object.status = .number(Double(status)) }
  if let problem {
    object.code = .string(String(problem.type.dropFirst("urn:diem:profile-hosting:".count)))
    object.status = .number(Double(problem.status))
    object.detail = .string(problem.detail)
    object.retryAfter = problem.retryAfter.map { .number(Double($0)) } ?? .null
    let labels = JSObject.global.Array.function!.new()
    for item in problem.labels {
      let label = JSObject()
      label.label = .string(item.label)
      label.reason = .string(item.reason)
      label.requiredBits = item.requiredBits.map { .number(Double($0)) } ?? .null
      _ = labels.push!(label)
    }
    object.labels = .object(labels)
  }
  return exception
}
